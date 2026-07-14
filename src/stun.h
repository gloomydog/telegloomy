#pragma once
#include "common.h"

typedef enum { NAT_UNKNOWN=0, NAT_CONE, NAT_SYMMETRIC } nat_type_t;

/* Two STUN probes to different servers from the same socket; compares the
 * mapped endpoints. Same mapping => endpoint-independent (cone, punchable);
 * different => symmetric. *mapped gets a discovered srflx (if any). */
nat_type_t nat_detect(int fd, ep_t *mapped);

/* STUN Binding Request (RFC 5389). *out receives the server-reflexive endpoint. */
int stun_query(const char *host, const char *port, ep_t *out);
/* Same, but issued from an existing (bound) UDP socket -- required so the
 * mapping matches the socket used for hole punching + data. */
int stun_query_on(int fd, const char *host, const char *port, ep_t *out);
