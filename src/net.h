#pragma once
#include "common.h"
#include <stdint.h>
#include <sys/socket.h>

/* ep_t <-> sockaddr conversions. */
socklen_t ep_to_sockaddr(const ep_t *ep, struct sockaddr_storage *ss);
void      sockaddr_to_ep(const struct sockaddr *sa, ep_t *ep);
int       ep_eq(const ep_t *a, const ep_t *b);

/* Bind a UDP socket on the given family (4 or 6), any local port.
 * Returns fd (>=0) and fills *bound with the local endpoint. */
int  udp_bind(int family, ep_t *bound);

/* Bind a UDP socket on 0.0.0.0 / :: (any interface), any port. */
int udp_bind_any(int family, uint16_t port, ep_t *bound);   /* port=0: any */

/* Dual-stack (IPv6+IPv4) UDP socket; -1 if IPv6 unavailable. */
int  udp_bind_dual(uint16_t port, ep_t *bound);   /* port=0: any */
/* ep -> sockaddr for a socket of the given family (AF_INET / AF_INET6). */
socklen_t ep_to_sa_fam(int family, const ep_t *ep, struct sockaddr_storage *ss);
