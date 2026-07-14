#pragma once
#include <stdint.h>
#include <stddef.h>

/* An endpoint: IPv4 or IPv6 address + port. */
typedef struct {
    uint8_t  family;    /* 4 or 6                                   */
    uint8_t  addr[16];  /* network byte order; IPv4 lives in [0..3] */
    uint16_t port;      /* host byte order                          */
} ep_t;

enum { CAND_HOST = 1, CAND_SRFLX = 2 };  /* candidate types */

typedef struct {
    uint8_t type;   /* CAND_HOST | CAND_SRFLX */
    ep_t    ep;
} candidate_t;
