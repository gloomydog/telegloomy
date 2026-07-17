#include "punch.h"
#include "net.h"
#include <string.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sodium.h>

/*
 * UDP hole punching, shaped to look like STUN and authenticated with a MAC.
 *
 * Packets are deliberately shaped like STUN Binding Requests / Responses
 * (RFC 5389 magic cookie). Some carrier and mobile networks treat
 * unrecognised small UDP payloads differently from STUN traffic, and looking
 * like STUN measurably improves reachability. A real STUN server that receives
 * one ignores it: the transaction id matches nothing it issued.
 *
 * Unlike a bare STUN packet, every punch carries a crypto_auth MAC over its
 * header, keyed by SUBKEY_PUNCH (derived from the PAKE master K, which is
 * already established over signalling *before* punching begins). So the punch
 * is authenticated -- an observer cannot forge or inject one, and only the
 * peer holding K can open the path. This MAC replaces nat_traverse's cleartext
 * token, which nat_traverse could not authenticate because its handshake runs
 * after the punch, not before.
 *
 * Confirmation follows nat_traverse's proven approach: the path is confirmed
 * on the *actual source* of the peer's packets, never on the candidate it
 * advertised, because a peer's NAT may map a different port toward us than the
 * one it announced (common on carrier NAT). Either an authenticated PING or a
 * PONG that echoes our challenge confirms the path -- both directions are being
 * blasted at once, so whichever crosses the wire first wins.
 *
 * Wire format (52 bytes):
 *
 *   off  field       size          value
 *   0    type        be16          0x0001 PING / 0x0101 PONG  (STUN msg type)
 *   2    length      be16          32                         (STUN attr len)
 *   4    cookie      be32          0x2112A442                 (STUN magic)
 *   8    challenge   8             sender's per-session nonce  \  STUN 12-byte
 *   16   pad         4             zero                        /  transaction id
 *   20   mac         32            crypto_auth over bytes 0..19
 */

#define STUN_MAGIC 0x2112A442u
#define PKT_PING   0x0001                     /* looks like a Binding Request  */
#define PKT_PONG   0x0101                     /* looks like a Binding Response */
#define HDRLEN     20                         /* STUN header: type+len+cookie+txid */
#define MACLEN     crypto_auth_BYTES          /* 32 */
#define PKTLEN     (HDRLEN + MACLEN)          /* 52 */

static long now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000L + t.tv_nsec/1000000L; }
static void sleep_ms(int ms){ struct timespec t={.tv_sec=ms/1000,.tv_nsec=(ms%1000)*1000000L}; nanosleep(&t,NULL); }

static void put16(uint8_t *p, uint16_t v){ p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static void put32(uint8_t *p, uint32_t v){ p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; }
static uint16_t get16(const uint8_t *p){ return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t get32(const uint8_t *p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }

/* Build a STUN-shaped, MAC-authenticated punch packet. chal is 8 bytes. */
static void build(uint8_t pkt[PKTLEN], uint16_t type, const uint8_t chal[8], const uint8_t key[32]) {
    put16(pkt,   type);
    put16(pkt+2, MACLEN);
    put32(pkt+4, STUN_MAGIC);
    memcpy(pkt+8, chal, 8);
    memset(pkt+16, 0, 4);
    crypto_auth(pkt+HDRLEN, pkt, HDRLEN, key);   /* MAC over the 20-byte header */
}

/* Validate shape and authenticity. crypto_auth_verify is constant time, so a
 * near-miss key does not leak how close it was. Also rejects a stray real STUN
 * response: the MAC over its header will not verify. */
static int punch_valid(const uint8_t *pkt, ssize_t n, const uint8_t key[32]) {
    if (n != PKTLEN) return 0;
    if (get32(pkt+4) != STUN_MAGIC) return 0;
    uint16_t type = get16(pkt);
    if (type != PKT_PING && type != PKT_PONG) return 0;
    return crypto_auth_verify(pkt+HDRLEN, pkt, HDRLEN, key) == 0;
}

int punch_run(punch_ctx *c, int timeout_ms, ep_t *chosen) {
    const int interval = 60;                  /* resend every 60 ms */
    uint8_t chal[8];
    randombytes_buf(chal, sizeof chal);       /* our fresh per-session challenge */

    /* Match the socket's family; on a dual-stack (AF_INET6) socket, IPv4
     * candidates go out v4-mapped. Precompute each remote's sockaddr. */
    struct sockaddr_storage lss; socklen_t ll = sizeof lss;
    getsockname(c->fd, (struct sockaddr *)&lss, &ll);
    int fam = lss.ss_family;

    struct sockaddr_storage rss[MAX_CANDS]; socklen_t rsl[MAX_CANDS];
    for (int i = 0; i < c->nremote; i++) {
        if (fam == AF_INET && c->remote[i].family == 6) { rsl[i] = 0; continue; } /* unreachable on v4 sock */
        rsl[i] = ep_to_sa_fam(fam, &c->remote[i], &rss[i]);
    }

    long start = now_ms(), last_send = -1000;
    while (now_ms() - start < timeout_ms) {
        long now = now_ms();
        if (now - last_send >= interval) {
            uint8_t ping[PKTLEN]; build(ping, PKT_PING, chal, c->key);
            for (int i = 0; i < c->nremote; i++) {
                if (rsl[i] == 0) continue;
                sendto(c->fd, ping, PKTLEN, 0, (struct sockaddr *)&rss[i], rsl[i]);
            }
            last_send = now;
        }

        struct pollfd pf = { .fd = c->fd, .events = POLLIN };
        if (poll(&pf, 1, interval) <= 0 || !(pf.revents & POLLIN)) continue;

        uint8_t buf[128]; struct sockaddr_storage from; socklen_t fl = sizeof from;
        ssize_t n = recvfrom(c->fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (!punch_valid(buf, n, c->key)) continue;   /* forged / unrelated / stray STUN */

        if (get16(buf) == PKT_PING) {
            /* The peer's authenticated punch reached us: the path works, on the
             * address it actually came from. Reply PONG (echoing their
             * challenge, so they confirm too) and take this source as the path.
             * Confirming on the source rather than an advertised candidate is
             * what makes carrier NAT work. */
            uint8_t pong[PKTLEN]; build(pong, PKT_PONG, buf + 8, c->key);
            sendto(c->fd, pong, PKTLEN, 0, (struct sockaddr *)&from, fl);
            if (chosen) sockaddr_to_ep((struct sockaddr *)&from, chosen);
            connect(c->fd, (struct sockaddr *)&from, fl);   /* lock the flow */
            sodium_memzero(chal, sizeof chal);
            return 0;
        }
        /* PONG: a live round trip back to whoever we punched. It must echo the
         * fresh challenge we sent, which stops a captured PONG being replayed. */
        if (sodium_memcmp(buf + 8, chal, 8) == 0) {
            if (chosen) sockaddr_to_ep((struct sockaddr *)&from, chosen);
            connect(c->fd, (struct sockaddr *)&from, fl);
            sodium_memzero(chal, sizeof chal);
            return 0;
        }
    }
    sodium_memzero(chal, sizeof chal);
    return -1;
}

/* ------------------------------- keepalive ------------------------------ */

static pthread_t    g_ka_thread;
static volatile int g_ka_running = 0;
static int          g_ka_fd;
static uint8_t      g_ka_key[32];
static int          g_ka_interval;

static void *keepalive_loop(void *arg) {
    (void)arg;
    while (g_ka_running) {
        uint8_t chal[8]; randombytes_buf(chal, sizeof chal);
        uint8_t ping[PKTLEN]; build(ping, PKT_PING, chal, g_ka_key);
        send(g_ka_fd, ping, PKTLEN, 0);   /* socket is connect()ed to the peer */
        /* Wake often so shutdown is prompt rather than blocking a whole interval. */
        for (int slept = 0; slept < g_ka_interval && g_ka_running; slept += 100)
            sleep_ms(100);
    }
    return NULL;
}

int punch_start_keepalive(int fd, const uint8_t key[32], int interval_ms) {
    g_ka_fd = fd;
    memcpy(g_ka_key, key, 32);
    g_ka_interval = interval_ms;
    g_ka_running = 1;
    return pthread_create(&g_ka_thread, NULL, keepalive_loop, NULL);
}

void punch_stop_keepalive(void) {
    if (g_ka_running) {
        g_ka_running = 0;
        pthread_join(g_ka_thread, NULL);
        sodium_memzero(g_ka_key, sizeof g_ka_key);
    }
}
