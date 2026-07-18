#include "signaling.h"
#include "keys.h"
#include "stun.h"
#include "net.h"
#include "candidate.h"
#include "punch.h"
#include "transport.h"
#include "app.h"
#ifdef WITH_VOICE
#include "voice.h"
#include "audio_pipewire.h"
#include <pthread.h>
static void *audio_thread(void *a){ audio_pw_run((voice_t*)a, 48000, 960); return NULL; }
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sodium.h>
#include <signal.h>
#include <arpa/inet.h>

/* Punch attempts before falling back to relay, and the short barrier that
 * re-aligns both sides before each retry. Mirrors cwormhole's tuning. */
#define PUNCH_RETRIES          3     /* env: PUNCH_RETRIES */
#define PUNCH_TIMEOUT_MS       10000 /* per-attempt hole-punch window */
#define PUNCH_SYNC_TIMEOUT_MS  5000  /* short barrier for per-retry candidate re-exchange */
#define REFRESH_RESEND_MS      1500  /* re-publish our round candidates this often */

static long now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000L + t.tv_nsec/1000000L; }
static void sleep_ms(int ms){ struct timespec t={.tv_sec=ms/1000,.tv_nsec=(ms%1000)*1000000L}; nanosleep(&t,NULL); }

static volatile sig_atomic_t g_want_quit = 0;
static void on_term(int sig){ (void)sig; g_want_quit = 1; }

struct ui { app_t *app; int peer_gone; };

static const char *basename2(const char *p){ const char *b=strrchr(p,'/'); return b?b+1:p; }

/* Strong pairing code, ambiguous glyphs (0/O/1/I/l) excluded. ~5.8 bits/char. */
static void generate_room_code(char *out, int len){
    static const char cs[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
    int n = (int)(sizeof cs - 1);
    for (int i=0;i<len;i++) out[i] = cs[randombytes_uniform((uint32_t)n)];
    out[len] = 0;
}

/* relay-fallback datapath: send transport packets over Nostr, tagged 'D'. */
static int relay_send(void *user, const uint8_t *wire, size_t len){
    signaling_t *sig = user;
    uint8_t out[1 + 1200];
    if (len > sizeof out - 1) return -1;
    out[0] = 'D'; memcpy(out+1, wire, len);
    return signaling_send(sig, out, len+1);
}

static void on_chat(void *u, const char *text, size_t len){
    (void)u; printf("\rpeer> %.*s\n> ", (int)len, text); fflush(stdout);
}
static void on_bye(void *u){ struct ui *ui=u; ui->peer_gone=1; printf("\r[*] peer disconnected\n"); fflush(stdout); }
static void on_file(void *u, uint32_t id, const char *name, uint64_t got, uint64_t total, int done, int ok){
    struct ui *ui = u;
    if (!done){ printf("\r[recv %s] %llu/%llu\r", name,(unsigned long long)got,(unsigned long long)total); fflush(stdout); return; }
    if (!ok){ printf("\r[recv %s] HASH MISMATCH -- discarded\n> ", name); fflush(stdout); return; }
    uint64_t len=0; const uint8_t *d = app_inbound_data(ui->app, id, &len);
    char out[512]; snprintf(out,sizeof out,"received_%s", name);
    FILE *f=fopen(out,"wb"); if (f){ fwrite(d,1,len,f); fclose(f); printf("\r[recv %s] saved -> %s (%llu bytes)\n> ", name,out,(unsigned long long)len);}
    else printf("\r[recv %s] could not write file\n> ", name);
    fflush(stdout);
}

/* Re-measure + re-swap candidates before a punch retry, so an in-session retry
 * carries the same fresh state a hand restart would. Two things go stale between
 * the one-time pre-loop exchange and a later attempt: (1) our server-reflexive
 * port -- the NAT mapping can drift, or may only just have warmed, since the
 * first STUN probe, so the port the peer was told to aim at is wrong; (2) window
 * alignment -- relay jitter staggers when each side finishes the first exchange,
 * and a plain retry loop preserves that skew. Re-running STUN fixes (1);
 * re-exchanging over the relay doubles as a barrier that re-aligns both sides for
 * (2). The barrier uses a SHORT timeout: if the peer already confirmed and moved
 * on, it is no longer answering, so we must not block -- we time out in a few
 * seconds and let the caller punch once more, which confirms on the peer's
 * keepalive PINGs. Messages are round-tagged ('R'<attempt>) so a leftover from an
 * earlier round (or the pre-loop 'C' exchange) is never mistaken for this round's
 * answer; if the two sides drift onto different attempt numbers the tags simply
 * miss, the barrier times out, and each punches anyway -- degrading to the old
 * behaviour rather than deadlocking.
 *
 * Returns 0 and rebuilds pc->remote from the peer's fresh candidates on a
 * successful swap; -1 (pc left unchanged) if the barrier timed out. */
static int refresh_candidates(signaling_t *sig, const uint8_t sk[32], int fd, int dual,
                              int attempt, candidate_t *cands, int nc, int srflx_idx,
                              int srflx6_idx, punch_ctx *pc){
    if (srflx_idx >= 0){
        ep_t srflx;
        if (stun_query_on(fd, "stun.l.google.com", "19302", &srflx) == 0)
            cands[srflx_idx].ep = srflx;   /* replace the possibly-stale mapping */
    }
    if (srflx6_idx >= 0){
        ep_t srflx6;
        if (stun_query6_on(fd, "stun.l.google.com", "19302", &srflx6) == 0)
            cands[srflx6_idx].ep = srflx6;
    }

    uint8_t wire[512]; int wlen = cand_serialize(cands, nc, wire, sizeof wire);
    if (wlen < 0) return -1;
    uint8_t sealed[600]; size_t slen = 0;
    if (cand_seal(sk, wire, wlen, sealed, &slen) != 0) return -1;
    uint8_t msg[602]; msg[0]='R'; msg[1]=(uint8_t)attempt; memcpy(msg+2, sealed, slen);
    size_t msglen = slen + 2;

    /* Publish our round candidates, then wait for the peer's matching round,
     * re-publishing periodically (ephemeral relay events aren't stored, so a
     * peer that reaches the barrier a beat later still needs to see ours). */
    signaling_send(sig, msg, msglen);
    long deadline = now_ms() + PUNCH_SYNC_TIMEOUT_MS;
    long next_resend = now_ms() + REFRESH_RESEND_MS;
    for (;;){
        long now = now_ms();
        if (now >= deadline) return -1;   /* peer not answering this round -- likely already up */
        if (now >= next_resend){ signaling_send(sig, msg, msglen); next_resend = now + REFRESH_RESEND_MS; }

        uint8_t rbuf[700]; size_t rlen = 0;
        if (signaling_try_recv(sig, rbuf, sizeof rbuf, &rlen) != 0){ sleep_ms(50); continue; }
        if (rlen < 2 || rbuf[0] != 'R' || rbuf[1] != (uint8_t)attempt) continue; /* stale / other round */

        uint8_t rwire[512]; size_t rwlen = 0;
        if (cand_open(sk, rbuf+2, rlen-2, rwire, &rwlen) != 0) continue;
        candidate_t rem[MAX_CANDS]; int nr = cand_deserialize(rwire, rwlen, rem, MAX_CANDS);
        if (nr <= 0) return -1;
        pc->nremote = 0;
        for (int i=0;i<nr;i++){ if(!dual && rem[i].ep.family==6) continue; pc->remote[pc->nremote++]=rem[i].ep; }
        return pc->nremote > 0 ? 0 : -1;
    }
}

int main(int argc, char **argv){
    if (argc < 2 || (strcmp(argv[1],"create")!=0 && strcmp(argv[1],"join")!=0)){
        fprintf(stderr,"usage:\n  %s create [relay_host]        # prints a strong pairing code\n"
                       "  %s join <code> [relay_host]   # use the code from the other side\n", argv[0], argv[0]);
        return 1;
    }
    int is_init = strcmp(argv[1],"create")==0;
    if (!is_init && argc < 3){ fprintf(stderr,"join needs the pairing code: %s join <code> [relay_host]\n", argv[0]); return 1; }
    if (sodium_init() < 0) return 1;
    signal(SIGPIPE, SIG_IGN);   /* never die on a write to a closed relay/socket */
    signal(SIGINT,  on_term);   /* Ctrl+C: quit cleanly (frees the socket) instead of dying raw */
    signal(SIGTERM, on_term);   /* e.g. `kill` without -9 */

    char codebuf[64]; const char *pass; const char *relay;
    if (is_init){
        generate_room_code(codebuf, 12);
        pass = codebuf;
        relay = argc>2 ? argv[2] : NULL;
        fprintf(stderr, "\n  ==== pairing code: %s ====\n  on the other machine run:  %s join %s\n\n",
                codebuf, argv[0], codebuf);
    } else {
        pass  = argv[2];
        relay = argc>3 ? argv[3] : NULL;
    }

    fprintf(stderr,"[*] role %s\n", is_init?"A(create)":"B(join)");
    signaling_t *sig = signaling_open(relay, pass, is_init);
    if (!sig){ fprintf(stderr,"signaling_open failed\n"); return 1; }

    uint8_t K[32];
    fprintf(stderr,"[*] waiting for peer + PAKE handshake...\n");
    if (signaling_derive_key(sig, K) != 0){ fprintf(stderr,"handshake failed\n"); signaling_close(sig); return 1; }

    /* Fixed UDP port so a firewall (ufw/Windows FW/etc.) only needs one rule.
     * Override with P2P_PORT if it's already in use. */
    uint16_t port = 58712;   /* avoid the WireGuard-standard 51820, which many VPN setups use */
    const char *pe = getenv("P2P_PORT");
    if (pe && *pe) { long v = strtol(pe, NULL, 10); if (v > 0 && v < 65536) port = (uint16_t)v; }

    ep_t local; int dual = 1;
    int fd = udp_bind_dual(port, &local);
    if (fd < 0){ dual = 0; fd = udp_bind_any(4, port, &local); }
    if (fd < 0){
        fprintf(stderr,"[!] bind to UDP port %u failed (already in use?). Try:\n"
                       "      P2P_PORT=<other-port> %s %s ...\n", port, argv[0], argv[1]);
        return 1;
    }
    fprintf(stderr,"[*] socket: %s, UDP port %u -- open this port (in) on your firewall\n",
            dual?"dual-stack (IPv6-capable, IPv4 fallback)":"IPv4-only", port);

    candidate_t cands[MAX_CANDS]; int nc = cand_collect_host(cands, MAX_CANDS);
    for (int i=0;i<nc;i++) cands[i].ep.port = local.port;
    ep_t srflx; nat_type_t nat = nat_detect(fd, &srflx);
    fprintf(stderr,"[*] NAT type: %s\n",
            nat==NAT_CONE?"cone (punchable)":nat==NAT_SYMMETRIC?"symmetric (punch may fail)":"unknown");
    int srflx_idx = -1;
    if (nat != NAT_UNKNOWN && nc < MAX_CANDS){ srflx_idx = nc; cands[nc].type=CAND_SRFLX; cands[nc].ep=srflx; nc++; }

    /* IPv6 server-reflexive: the exact global v6 address the kernel sources from
     * toward the internet. Advertising it (and sending from it) aligns the
     * pinholes both peers open -- without it, a host's many SLAAC/privacy v6
     * addresses leave each side targeting an address the other never sent from,
     * and every punch is firewall-dropped. Only meaningful on a dual-stack sock. */
    int srflx6_idx = -1;
    if (dual && nc < MAX_CANDS){
        ep_t srflx6;
        if (stun_query6_on(fd, "stun.l.google.com", "19302", &srflx6) == 0){
            srflx6_idx = nc; cands[nc].type=CAND_SRFLX; cands[nc].ep=srflx6; nc++;
        }
    }
    for (int i=0;i<nc;i++){
        char ipbuf[INET6_ADDRSTRLEN]; inet_ntop(cands[i].ep.family==6?AF_INET6:AF_INET, cands[i].ep.addr, ipbuf, sizeof ipbuf);
        fprintf(stderr,"[*] our candidate: %s %s:%u\n", cands[i].type==CAND_SRFLX?"srflx":"host ", ipbuf, cands[i].ep.port);
    }

    /* seal + exchange candidates (tagged 'C') */
    uint8_t sk[32]; derive_subkey(sk, SUBKEY_SIGNAL, K);
    uint8_t wire[512]; int wlen = cand_serialize(cands, nc, wire, sizeof wire);
    uint8_t sealed[600]; size_t slen=0; cand_seal(sk, wire, wlen, sealed, &slen);
    uint8_t tagged[601]; tagged[0]='C'; memcpy(tagged+1, sealed, slen);
    signaling_send(sig, tagged, slen+1);

    uint8_t rblob[700]; size_t rlen=0;
    do { if (signaling_recv(sig, rblob, sizeof rblob, &rlen)!=0){ fprintf(stderr,"no peer candidates\n"); return 1; } }
    while (rlen<1 || rblob[0]!='C');
    uint8_t rwire[512]; size_t rwlen=0;
    if (cand_open(sk, rblob+1, rlen-1, rwire, &rwlen)!=0){ fprintf(stderr,"candidate decrypt failed\n"); return 1; }
    candidate_t rem[MAX_CANDS]; int nr = cand_deserialize(rwire, rwlen, rem, MAX_CANDS);
    if (nr<=0){ fprintf(stderr,"bad peer candidates\n"); return 1; }
    for (int i=0;i<nr;i++){
        char ipbuf[INET6_ADDRSTRLEN]; inet_ntop(rem[i].ep.family==6?AF_INET6:AF_INET, rem[i].ep.addr, ipbuf, sizeof ipbuf);
        fprintf(stderr,"[*] peer candidate: %s %s:%u\n", rem[i].type==CAND_SRFLX?"srflx":"host ", ipbuf, rem[i].ep.port);
    }
    /* sk (SUBKEY_SIGNAL) stays live: the retry loop re-seals refreshed
     * candidates with it. Zeroed once punching is done, below. */
    fprintf(stderr,"[*] got %d peer candidate(s); punching...\n", nr);

    punch_ctx pc; memset(&pc,0,sizeof pc); pc.fd=fd;
    derive_subkey(pc.key, SUBKEY_PUNCH, K);
    pc.nremote=0;
    for (int i=0;i<nr;i++){ if(!dual && rem[i].ep.family==6) continue; pc.remote[pc.nremote++]=rem[i].ep; }
    if (pc.nremote==0){ fprintf(stderr,"no reachable peer candidates\n"); return 1; }
    ep_t chosen;
    int relay_mode = 0;
    struct ui ui = {0};
    transport_t *t = transport_new(fd, is_init?0:1, K, NULL, NULL, NULL);
    sodium_memzero(K, sizeof K);

    /* Try punching several times before giving up on a direct path. A single
     * failed attempt is often just a near-miss: the two peers' punch windows only
     * briefly overlapped (relay latency staggers when each side finishes the
     * candidate exchange and starts punching), or the first PINGs hit a still-cold
     * NAT mapping. Re-running punch_run back-to-back widens the combined overlap
     * and lets the already-warmed mapping carry the next attempt -- the same
     * reason ending the session and starting over by hand sometimes connects. Each
     * retry first refreshes candidates (re-STUN + re-exchange), which also acts as
     * a shared barrier so both sides' punch windows stay aligned; if one side
     * confirms first, its keepalive PINGs nudge the peer, whose own punch_run
     * confirms on any authenticated PING. */
    int retries = PUNCH_RETRIES;
    const char *re = getenv("PUNCH_RETRIES");
    if (re && *re){ long v=strtol(re,NULL,10); if(v>=1 && v<=100) retries=(int)v; }

    int punched = 0;
    for (int attempt=1; attempt<=retries; attempt++){
        if (attempt > 1){
            fprintf(stderr,"[*] refreshing candidates (re-STUN + re-exchange) before retry...\n");
            refresh_candidates(sig, sk, fd, dual, attempt, cands, nc, srflx_idx, srflx6_idx, &pc);
        }
        fprintf(stderr,"[*] punching (UDP hole punch, up to %ds, attempt %d/%d)...\n",
                PUNCH_TIMEOUT_MS/1000, attempt, retries);
        if (punch_run(&pc, PUNCH_TIMEOUT_MS, &chosen) == 0){ punched = 1; break; }
        if (attempt < retries)
            fprintf(stderr,"[!] punch attempt %d/%d failed -- retrying...\n", attempt, retries);
    }
    sodium_memzero(sk, sizeof sk);

    if (punched){
        char ipbuf[INET6_ADDRSTRLEN];
        inet_ntop(chosen.family==6?AF_INET6:AF_INET, chosen.addr, ipbuf, sizeof ipbuf);
        fprintf(stderr,"[+] direct path established (%s) -> %s:%u\n",
                chosen.family==6?"IPv6":"IPv4", ipbuf, chosen.port);
        punch_start_keepalive(fd, pc.key, 15000);   /* hold the NAT mapping / conntrack open */
        signaling_close(sig); sig=NULL;
    } else {
        fprintf(stderr,"[!] hole punch failed after %d attempts -- relaying over Nostr (chat ok; file slow; voice off)\n", retries);
        relay_mode = 1;
        transport_set_relay(t, relay_send, sig);   /* keep sig open as the datapath */
    }
    sodium_memzero(pc.key, sizeof pc.key);

    app_t *app = app_new(t, on_chat, on_file, &ui);
    ui.app = app;
    app_set_on_bye(app, on_bye);
#ifdef WITH_VOICE
    voice_t *voice = NULL; pthread_t vthr; int in_call = 0;
#endif

    printf("connected%s. type to chat; '/file <path>' to send;",
           relay_mode?" (relayed)":"");
#ifdef WITH_VOICE
    if (!relay_mode) printf(" '/call'/'/hangup' voice;");
#endif
    printf(" '/quit' to exit.\n> "); fflush(stdout);

    char line[4096];
    for (;;){
        if (g_want_quit){
            fprintf(stderr, "\n[*] signal received, disconnecting...\n");
            app_send_bye(app);
            for (int i=0;i<60 && transport_reliable_inflight(t)>0;i++){
                if (relay_mode && sig){ uint8_t d[1400]; size_t dl;
                    while (signaling_try_recv(sig,d,sizeof d,&dl)==0) if(dl>=1&&d[0]=='D') transport_inject(t,d+1,dl-1); }
                app_poll(app,10);
            }
            break;
        }
        struct pollfd pf={.fd=0,.events=POLLIN};
        if (poll(&pf,1,0)>0 && (pf.revents&POLLIN)){
            if (!fgets(line,sizeof line,stdin)) break;
            size_t L=strlen(line); if (L && line[L-1]=='\n') line[--L]=0;
            if (strcmp(line,"/quit")==0){
                app_send_bye(app);
                for (int i=0;i<60 && transport_reliable_inflight(t)>0;i++){
                    if (relay_mode && sig){ uint8_t d[1400]; size_t dl;
                        while (signaling_try_recv(sig,d,sizeof d,&dl)==0) if(dl>=1&&d[0]=='D') transport_inject(t,d+1,dl-1); }
                    app_poll(app,10);
                }
                break;
            }
            else if (strncmp(line,"/file ",6)==0){
                const char *path=line+6; FILE *f=fopen(path,"rb");
                if (!f){ printf("cannot open %s\n> ",path); fflush(stdout); }
                else { fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
                    uint8_t *buf=malloc(sz>0?sz:1);
                    if (fread(buf,1,sz,f)==(size_t)sz){ app_send_file(app, basename2(path), buf, sz);
                        printf("[send] %s (%ld bytes) queued\n> ", basename2(path), sz); }
                    free(buf); fclose(f); fflush(stdout); }
            }
#ifdef WITH_VOICE
            else if (strcmp(line,"/call")==0){
                if (relay_mode) printf("[voice] disabled over the relay path\n> ");
                else if (!in_call){ voice=voice_new(t,48000,960); transport_set_unreliable_cb(t,voice_on_packet,voice);
                    pthread_create(&vthr,NULL,audio_thread,voice); in_call=1; printf("[voice] call started (48kHz mono)\n> "); }
                else printf("[voice] already in a call\n> ");
                fflush(stdout);
            }
            else if (strcmp(line,"/hangup")==0){
                if (in_call){ audio_pw_quit(); pthread_join(vthr,NULL); transport_set_unreliable_cb(t,NULL,NULL);
                    voice_free(voice); voice=NULL; in_call=0; printf("[voice] call ended\n> "); }
                else printf("[voice] not in a call\n> ");
                fflush(stdout);
            }
#endif
            else if (L>0){ app_send_chat(app,line,L); printf("> "); fflush(stdout); }
            else { printf("> "); fflush(stdout); }
        }
        if (relay_mode && sig){
            uint8_t d[1400]; size_t dl;
            while (signaling_try_recv(sig, d, sizeof d, &dl)==0)
                if (dl>=1 && d[0]=='D') transport_inject(t, d+1, dl-1);
        }
        app_poll(app, 20);
        if (ui.peer_gone) break;
    }
#ifdef WITH_VOICE
    if (in_call){ audio_pw_quit(); pthread_join(vthr,NULL); voice_free(voice); }
#endif
    punch_stop_keepalive();   /* no-op if we fell back to relay */
    app_free(app); transport_free(t); if (sig) signaling_close(sig); close(fd);
    printf("\nbye.\n");
    return 0;
}
