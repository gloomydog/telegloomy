#pragma once
#include "common.h"
#include "candidate.h"

typedef struct {
    int     fd;                    /* bound UDP socket (shared w/ STUN + data) */
    uint8_t key[32];               /* SUBKEY_PUNCH derived from master K       */
    ep_t    remote[MAX_CANDS];     /* remote candidate endpoints to probe      */
    int     nremote;
} punch_ctx;

/* Simultaneously probe all remote candidates until a path is confirmed, then
 * connect() fd to it. On success returns 0 and writes the working endpoint to
 * *chosen; returns -1 on timeout.
 *
 * The confirmed endpoint is the *actual source* of the peer's packets, never
 * the candidate it advertised: a peer's NAT may map a different port toward us
 * than the one it announced (common on carrier NAT), and that mapping is the
 * only address that works. */
int punch_run(punch_ctx *c, int timeout_ms, ep_t *chosen);

/* Keep the NAT mapping / firewall state alive once the path is up. fd must be
 * the connect()ed punch socket. The interval must sit well under the shortest
 * timeout on the path: Linux conntrack defaults to 30 s for unconfirmed UDP
 * and 120 s once traffic has flowed both ways, and carrier NATs are often far
 * more aggressive; 15 s is a reasonable default.
 *
 * The keepalive keeps sending punch PINGs, so it also nudges a peer that has
 * not confirmed yet (its punch loop confirms on any authenticated PING). */
int  punch_start_keepalive(int fd, const uint8_t key[32], int interval_ms);
void punch_stop_keepalive(void);
