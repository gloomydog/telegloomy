#pragma once
#include "common.h"
#include "candidate.h"

typedef struct {
    int     fd;                    /* bound UDP socket (shared w/ STUN + data) */
    uint8_t key[32];               /* SUBKEY_PUNCH derived from master K       */
    ep_t    remote[MAX_CANDS];     /* remote candidate endpoints to probe      */
    int     nremote;
} punch_ctx;

/* Simultaneously probe all remote candidates until one path is confirmed
 * bidirectionally (or timeout). On success returns 0, writes the working
 * endpoint to *chosen, and connect()s fd to it. Returns -1 on timeout. */
int punch_run(punch_ctx *c, int timeout_ms, ep_t *chosen);
