#include "signaling.h"
#include "chat_session.h"
#include "cpace.h"
#include "envelope.h"
#include "nostr_event.h"
#include "ws_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sodium.h>
#include <stdatomic.h>

#define KIND    20077
#define EVBUF   16384
#define MAXRELAY 4
#define QCAP    256

static const char *DEFAULT_RELAYS[] = { "relay.damus.io", "relay.primal.net", "relay.nostr.band", "nos.lol" };
#define NDEFAULT (int)(sizeof(DEFAULT_RELAYS)/sizeof(DEFAULT_RELAYS[0]))

struct qitem { char pub[65]; envelope_t env; struct qitem *next; };

struct signaling {
    ws_client_t ws[MAXRELAY];
    char relaylist[MAXRELAY][128]; int nrelaylist;
    _Atomic int ready[MAXRELAY];
    int active[MAXRELAY], nactive;

    nostr_identity_t me;
    chat_session sess;
    int is_initiator;
    char room_code[ROOM_CODE_MAXLEN];
    char room_id[ENVELOPE_ROOM_MAXLEN];
    char my_role[2], peer_role[2];
    char sub_id[17];

    pthread_mutex_t lock;
    pthread_cond_t  cond;
    char pending[EVBUF];
    struct qitem *qh, *qt; int qlen;
    _Atomic int running, handshake_done;
    pthread_t readers[MAXRELAY];
    struct { signaling_t *s; int idx; } rargs[MAXRELAY];
};

static int derive_room_id(const char *code, char *out, size_t cap) {
    /* Per-code salt (public; just stops a single global precomputation table). */
    unsigned char salt[crypto_pwhash_SALTBYTES];
    char pre[160]; snprintf(pre, sizeof pre, "telegloomy-nostr-salt-v1:%s", code);
    crypto_generichash(salt, sizeof salt, (const unsigned char*)pre, strlen(pre), NULL, 0);
    /* Argon2id key-stretch so the public Nostr tag can't be brute-forced back
     * to the passphrase with a fast offline dictionary attack. Both peers run
     * identical params, so the derived tag matches. */
    unsigned char tag[16];
    if (crypto_pwhash(tag, sizeof tag, code, strlen(code), salt,
                      crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) return -1;
    sodium_bin2hex(out, cap, tag, sizeof tag);
    return 0;
}

static void parse_relay(const char *in, char *host, size_t hcap, int *port) {
    *port = 443; const char *h = in;
    if (strncmp(h,"wss://",6)==0) h+=6; else if (strncmp(h,"ws://",5)==0){ h+=5; *port=80; }
    strncpy(host,h,hcap-1); host[hcap-1]=0;
    char *sl=strchr(host,'/'); if(sl)*sl=0;
    char *co=strchr(host,':'); if(co){*co=0; int p=atoi(co+1); if(p>0&&p<65536) *port=p;}  /* ignore out-of-range port, keep scheme default */
}

static int make_event(signaling_t *s, envelope_type_t type, const char *role,
                      const uint8_t *data, size_t dlen, char *out, size_t cap) {
    char env[EVBUF], ev[EVBUF];
    if (envelope_build(env, sizeof env, s->room_id, type, role, data, dlen) < 0) return -1;
    if (nostr_build_event(&s->me, KIND, s->room_id, env, ev, sizeof ev) < 0) return -1;
    if (nostr_wrap_event_msg(ev, out, cap) < 0) return -1;
    return 0;
}

static void publish_all(signaling_t *s, const char *msg) {
    for (int k=0;k<s->nactive;k++)
        ws_client_send_text(&s->ws[s->active[k]], (const uint8_t*)msg, strlen(msg));
}
static int publish(signaling_t *s, envelope_type_t type, const char *role,
                   const uint8_t *data, size_t dlen) {
    char msg[EVBUF];
    if (make_event(s, type, role, data, dlen, msg, sizeof msg) != 0) return -1;
    publish_all(s, msg); return 0;
}
static void set_pending(signaling_t *s, const char *msg) {
    pthread_mutex_lock(&s->lock);
    strncpy(s->pending, msg, sizeof s->pending -1); s->pending[sizeof s->pending -1]=0;
    pthread_mutex_unlock(&s->lock);
}

static void push_event(signaling_t *s, const char *pub, const envelope_t *env) {
    pthread_mutex_lock(&s->lock);
    if (s->qlen < QCAP) {
        struct qitem *it = malloc(sizeof *it);
        if (it) { strncpy(it->pub, pub, sizeof it->pub -1); it->pub[64]=0; it->env=*env; it->next=NULL;
                  if (s->qt) s->qt->next=it; else s->qh=it; s->qt=it; s->qlen++;
                  pthread_cond_signal(&s->cond); }
    }
    pthread_mutex_unlock(&s->lock);
}
static int pop_event(signaling_t *s, int timeout_ms, char *out_pub, envelope_t *out_env) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms/1000; ts.tv_nsec += (long)(timeout_ms%1000)*1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&s->lock);
    while (!s->qh && s->running) { if (pthread_cond_timedwait(&s->cond,&s->lock,&ts)!=0) break; }
    int got=0;
    if (s->qh) { struct qitem *it=s->qh; s->qh=it->next; if(!s->qh) s->qt=NULL; s->qlen--;
                 if(out_pub){strncpy(out_pub,it->pub,64);out_pub[64]=0;} if(out_env)*out_env=it->env; free(it); got=1; }
    pthread_mutex_unlock(&s->lock);
    return got;
}

static void *reader(void *arg) {
    struct { signaling_t *s; int idx; } *r = arg;
    signaling_t *s = r->s; int i = r->idx;
    uint8_t rx[EVBUF];
    while (s->running) {
        int n = ws_client_recv_text(&s->ws[i], rx, sizeof rx -1);
        if (n <= 0) break;
        rx[n]=0;
        char pub[65], content[EVBUF];
        if (nostr_parse_incoming((char*)rx, pub, sizeof pub, content, sizeof content) != 0) continue;
        if (strcmp(pub, s->me.pubkey_hex) == 0) continue;
        envelope_t env;
        if (envelope_parse(content, &env) != 0) continue;
        if (strcmp(env.room_id, s->room_id) != 0) continue;
        push_event(s, pub, &env);
    }
    return NULL;
}

static void *resender(void *arg) {
    signaling_t *s = arg;
    while (!s->handshake_done) {
        char buf[EVBUF]; buf[0]=0;
        pthread_mutex_lock(&s->lock);
        if (s->pending[0]) { strncpy(buf,s->pending,sizeof buf -1); buf[sizeof buf -1]=0; }
        pthread_mutex_unlock(&s->lock);
        if (buf[0]) publish_all(s, buf);
        for (int i=0;i<10 && !s->handshake_done;i++) usleep(100*1000);
    }
    return NULL;
}

/* one connect attempt per relay, run in parallel (each connect is time-bounded
 * by ws_client's connect + handshake timeouts, so joining them all is safe). */
struct conn_arg { signaling_t *s; int slot; };
static void *conn_thread(void *a) {
    struct conn_arg *c = a; signaling_t *s = c->s; int k = c->slot;
    char host[128]; int port; parse_relay(s->relaylist[k], host, sizeof host, &port);
    if (ws_client_connect(&s->ws[k], host, port, "/") == 0) {
        char req[512]; nostr_build_req(s->sub_id, KIND, s->room_id, req, sizeof req);
        ws_client_send_text(&s->ws[k], (const uint8_t*)req, strlen(req));
        fprintf(stderr, "[*] connected: %s:%d\n", host, port);
        s->ready[k] = 1;
    } else {
        fprintf(stderr, "[!] relay %s:%d unavailable\n", host, port);
    }
    return NULL;
}

static void add_relay(signaling_t *s, const char *r) {
    if (s->nrelaylist >= MAXRELAY) return;
    char h[128]; int p; parse_relay(r, h, sizeof h, &p);
    for (int i=0;i<s->nrelaylist;i++){ char eh[128]; int ep; parse_relay(s->relaylist[i],eh,sizeof eh,&ep);
        if (strcmp(eh,h)==0) return; }               /* dedup by host */
    strncpy(s->relaylist[s->nrelaylist], r, 127); s->relaylist[s->nrelaylist][127]=0; s->nrelaylist++;
}

signaling_t *signaling_open(const char *relay, const char *passphrase, int is_initiator) {
    signaling_t *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    pthread_mutex_init(&s->lock,NULL); pthread_cond_init(&s->cond,NULL);
    s->is_initiator = is_initiator;
    strcpy(s->my_role,   is_initiator ? "A" : "B");
    strcpy(s->peer_role, is_initiator ? "B" : "A");
    strncpy(s->room_code, passphrase, sizeof s->room_code -1);
    if (nostr_identity_generate(&s->me) != 0) { free(s); return NULL; }
    fprintf(stderr, "[*] stretching passphrase (argon2)...\n");
    if (derive_room_id(passphrase, s->room_id, sizeof s->room_id) != 0) {
        fprintf(stderr, "[!] argon2 key-stretch failed (low memory?)\n");
        pthread_mutex_destroy(&s->lock); pthread_cond_destroy(&s->cond); free(s); return NULL;
    }
    unsigned char sid[8]; randombytes_buf(sid, sizeof sid);
    sodium_bin2hex(s->sub_id, sizeof s->sub_id, sid, sizeof sid);   /* separate src: no in-place aliasing */

    if (relay && *relay) add_relay(s, relay);
    for (int i=0;i<NDEFAULT;i++) add_relay(s, DEFAULT_RELAYS[i]);

    /* connect to all candidate relays in parallel, then join */
    pthread_t cths[MAXRELAY]; struct conn_arg cargs[MAXRELAY];
    for (int k=0;k<s->nrelaylist;k++){ cargs[k].s=s; cargs[k].slot=k; pthread_create(&cths[k],NULL,conn_thread,&cargs[k]); }
    for (int k=0;k<s->nrelaylist;k++) pthread_join(cths[k], NULL);

    for (int k=0;k<s->nrelaylist;k++) if (s->ready[k]) s->active[s->nactive++] = k;
    if (s->nactive == 0) { fprintf(stderr,"[!] no relays reachable\n"); pthread_mutex_destroy(&s->lock); pthread_cond_destroy(&s->cond); free(s); return NULL; }
    fprintf(stderr, "[*] subscribed on %d relay(s), tag %s\n", s->nactive, s->room_id);

    s->running = 1;
    for (int k=0;k<s->nactive;k++){ s->rargs[k].s=s; s->rargs[k].idx=s->active[k]; pthread_create(&s->readers[k],NULL,reader,&s->rargs[k]); }
    return s;
}

int signaling_derive_key(signaling_t *s, uint8_t K[32]) {
    if (session_begin(&s->sess, s->room_code, strlen(s->room_code),
                      s->room_id, strlen(s->room_id), s->is_initiator) != 0) return -1;
    char first[EVBUF];
    if (make_event(s, ENVELOPE_POINT, s->my_role, s->sess.cpace.my_point, CPACE_POINTBYTES, first, sizeof first) != 0) return -1;
    set_pending(s, first); publish_all(s, first);
    fprintf(stderr, "[*] published our CPace point (role %s)\n", s->my_role);

    s->handshake_done = 0;
    pthread_t th; pthread_create(&th, NULL, resender, s);

    int rc = -1;
    while (!s->handshake_done) {
        envelope_t env;
        if (!pop_event(s, 250, NULL, &env)) continue;
        if (env.type == ENVELOPE_POINT && s->sess.state == SESSION_WAIT_PEER_POINT
            && strcmp(env.role, s->peer_role) == 0) {
            if (session_on_peer_point(&s->sess, env.data) == 0) {
                uint8_t mac[CPACE_MACBYTES];
                cpace_compute_confirmation(&s->sess.cpace, s->my_role, mac);
                char msg[EVBUF];
                if (make_event(s, ENVELOPE_CONFIRM, s->my_role, mac, CPACE_MACBYTES, msg, sizeof msg)==0) {
                    set_pending(s, msg); publish_all(s, msg);
                }
                fprintf(stderr, "[*] peer point received; sent confirmation\n");
            } else fprintf(stderr, "[!] invalid peer point (wrong passphrase?)\n");
        } else if (env.type == ENVELOPE_CONFIRM && s->sess.state == SESSION_WAIT_CONFIRM
                   && strcmp(env.role, s->peer_role) == 0) {
            if (session_on_peer_confirm(&s->sess, s->peer_role, env.data) == 0) {
                memcpy(K, s->sess.cpace.session_key, 32); rc = 0;
                for (int i=0;i<4;i++){
                    char buf[EVBUF]; buf[0]=0;
                    pthread_mutex_lock(&s->lock);
                    if(s->pending[0]){strncpy(buf,s->pending,sizeof buf-1);buf[sizeof buf-1]=0;}
                    pthread_mutex_unlock(&s->lock);
                    if(buf[0]) publish_all(s,buf);
                    usleep(120*1000);
                }
                s->handshake_done = 1;
                fprintf(stderr, "[+] confirmation verified; shared key established\n");
            } else fprintf(stderr, "[!] confirmation MAC mismatch (wrong passphrase / MITM)\n");
        }
    }
    s->handshake_done = 1; pthread_join(th, NULL);
    return rc;
}

int signaling_send(signaling_t *s, const uint8_t *blob, size_t len) {
    return publish(s, ENVELOPE_MSG, "", blob, len);
}
static int pop_msg(signaling_t *s, int timeout_ms, uint8_t *buf, size_t cap, size_t *len) {
    envelope_t env;
    if (!pop_event(s, timeout_ms, NULL, &env)) return -1;
    if (env.type != ENVELOPE_MSG) return -1;
    if (env.data_len > cap) return -1;
    memcpy(buf, env.data, env.data_len); *len = env.data_len; return 0;
}
int signaling_recv(signaling_t *s, uint8_t *buf, size_t cap, size_t *len) {
    for (;;) { int r = pop_msg(s, 3600000, buf, cap, len); if (r==0) return 0; if (!s->running) return -1; }
}
int signaling_try_recv(signaling_t *s, uint8_t *buf, size_t cap, size_t *len) {
    return pop_msg(s, 0, buf, cap, len);
}

void signaling_close(signaling_t *s) {
    if (!s) return;
    s->running = 0; s->handshake_done = 1;
    pthread_mutex_lock(&s->lock); pthread_cond_broadcast(&s->cond); pthread_mutex_unlock(&s->lock);
    /* interrupt each reader's blocking recv, WAIT for it to exit, THEN free the
     * SSL/socket -- otherwise a reader can touch freed SSL / a destroyed lock. */
    for (int k=0;k<s->nactive;k++) ws_client_shutdown(&s->ws[s->active[k]]);
    for (int k=0;k<s->nactive;k++) pthread_join(s->readers[k], NULL);
    for (int k=0;k<s->nactive;k++) ws_client_close(&s->ws[s->active[k]]);
    struct qitem *it=s->qh; while(it){ struct qitem *n=it->next; free(it); it=n; }
    session_wipe(&s->sess);
    pthread_mutex_destroy(&s->lock); pthread_cond_destroy(&s->cond);
    sodium_memzero(s, sizeof *s); free(s);
}
