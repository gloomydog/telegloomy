#include "punch.h"
#include "net.h"
#include <string.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <sodium.h>

#define PKT_PING 0x01
#define PKT_PONG 0x02
#define HDR 9                                   /* type(1) + challenge(8) */
#define PKTLEN (HDR + crypto_auth_BYTES)        /* 9 + 32 = 41 */

static long now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static void build(uint8_t *pkt, uint8_t type, const uint8_t chal[8], const uint8_t key[32]) {
    pkt[0] = type;
    memcpy(pkt + 1, chal, 8);
    crypto_auth(pkt + HDR, pkt, HDR, key);      /* MAC over type+challenge */
}

int punch_run(punch_ctx *c, int timeout_ms, ep_t *chosen) {
    const int interval = 60;                    /* resend PINGs every 60ms */
    uint8_t chal[MAX_CANDS][8];
    for (int i = 0; i < c->nremote; i++) randombytes_buf(chal[i], 8);

    /* Match the socket's family; on a dual-stack (AF_INET6) socket, IPv4
     * candidates go out as v4-mapped. Precompute each remote's sockaddr. */
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
            for (int i = 0; i < c->nremote; i++) {
                if (rsl[i] == 0) continue;
                uint8_t pkt[PKTLEN]; build(pkt, PKT_PING, chal[i], c->key);
                sendto(c->fd, pkt, PKTLEN, 0, (struct sockaddr *)&rss[i], rsl[i]);
            }
            last_send = now;
        }
        struct pollfd pf = { .fd = c->fd, .events = POLLIN };
        if (poll(&pf, 1, interval) > 0 && (pf.revents & POLLIN)) {
            uint8_t buf[64]; struct sockaddr_storage from; socklen_t fl = sizeof from;
            ssize_t n = recvfrom(c->fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
            if (n != PKTLEN) continue;
            if (buf[0] != PKT_PING && buf[0] != PKT_PONG) continue;
            if (crypto_auth_verify(buf + HDR, buf, HDR, c->key) != 0) continue;  /* forged/unrelated */
            ep_t src; sockaddr_to_ep((struct sockaddr *)&from, &src);
            if (buf[0] == PKT_PING) {
                uint8_t pong[PKTLEN]; build(pong, PKT_PONG, buf + 1, c->key);    /* echo challenge */
                sendto(c->fd, pong, PKTLEN, 0, (struct sockaddr *)&from, fl);
            } else {                                                             /* PONG */
                for (int i = 0; i < c->nremote; i++)
                    if (ep_eq(&c->remote[i], &src) && memcmp(buf + 1, chal[i], 8) == 0) {
                        if (chosen) *chosen = src;
                        connect(c->fd, (struct sockaddr *)&from, fl);           /* lock the flow */
                        return 0;
                    }
            }
        }
    }
    return -1;
}
