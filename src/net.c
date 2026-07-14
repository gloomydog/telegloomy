#include "net.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

socklen_t ep_to_sockaddr(const ep_t *ep, struct sockaddr_storage *ss) {
    memset(ss, 0, sizeof *ss);
    if (ep->family == 6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons(ep->port);
        memcpy(&s->sin6_addr, ep->addr, 16);
        return sizeof *s;
    }
    struct sockaddr_in *s = (struct sockaddr_in *)ss;
    s->sin_family = AF_INET;
    s->sin_port = htons(ep->port);
    memcpy(&s->sin_addr, ep->addr, 4);
    return sizeof *s;
}

void sockaddr_to_ep(const struct sockaddr *sa, ep_t *ep) {
    memset(ep, 0, sizeof *ep);
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
        if (IN6_IS_ADDR_V4MAPPED(&s->sin6_addr)) {       /* ::ffff:a.b.c.d -> real v4 */
            ep->family = 4; ep->port = ntohs(s->sin6_port);
            memcpy(ep->addr, s->sin6_addr.s6_addr + 12, 4);
            return;
        }
        ep->family = 6; ep->port = ntohs(s->sin6_port);
        memcpy(ep->addr, &s->sin6_addr, 16);
    } else {
        const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
        ep->family = 4; ep->port = ntohs(s->sin_port);
        memcpy(ep->addr, &s->sin_addr, 4);
    }
}

int ep_eq(const ep_t *a, const ep_t *b) {
    if (a->family != b->family || a->port != b->port) return 0;
    return memcmp(a->addr, b->addr, a->family == 6 ? 16 : 4) == 0;
}

int udp_bind(int family, ep_t *bound) {
    int af = family == 6 ? AF_INET6 : AF_INET;
    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_storage ss; memset(&ss, 0, sizeof ss);
    socklen_t sl;
    if (af == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;
        s->sin6_family = AF_INET6; s->sin6_addr = in6addr_loopback; sl = sizeof *s;
    } else {
        struct sockaddr_in *s = (struct sockaddr_in *)&ss;
        s->sin_family = AF_INET; s->sin_addr.s_addr = htonl(INADDR_LOOPBACK); sl = sizeof *s;
    }
    if (bind(fd, (struct sockaddr *)&ss, sl) != 0) { close(fd); return -1; }
    socklen_t bl = sizeof ss;
    getsockname(fd, (struct sockaddr *)&ss, &bl);
    if (bound) sockaddr_to_ep((struct sockaddr *)&ss, bound);
    return fd;
}

int udp_bind_any(int family, uint16_t port, ep_t *bound) {
    int af = family == 6 ? AF_INET6 : AF_INET;
    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) { fprintf(stderr, "[net] socket(%s) failed: %s\n", af==AF_INET6?"AF_INET6":"AF_INET", strerror(errno)); return -1; }
    struct sockaddr_storage ss; memset(&ss, 0, sizeof ss); socklen_t sl;
    if (af == AF_INET6) { struct sockaddr_in6 *s=(struct sockaddr_in6*)&ss; s->sin6_family=AF_INET6; s->sin6_addr=in6addr_any; s->sin6_port=htons(port); sl=sizeof *s; }
    else { struct sockaddr_in *s=(struct sockaddr_in*)&ss; s->sin_family=AF_INET; s->sin_addr.s_addr=htonl(INADDR_ANY); s->sin_port=htons(port); sl=sizeof *s; }
    if (bind(fd,(struct sockaddr*)&ss,sl)!=0) {
        fprintf(stderr, "[net] bind(%s:%u) failed: %s\n", af==AF_INET6?"[::]":"0.0.0.0", port, strerror(errno));
        close(fd); return -1;
    }
    socklen_t bl=sizeof ss; getsockname(fd,(struct sockaddr*)&ss,&bl);
    if (bound) sockaddr_to_ep((struct sockaddr*)&ss,bound);
    return fd;
}

/* Build a sockaddr appropriate for a socket of the given family. On an
 * AF_INET6 (dual-stack) socket, IPv4 endpoints are expressed as v4-mapped
 * (::ffff:a.b.c.d) so one socket can reach both address families. */
socklen_t ep_to_sa_fam(int family, const ep_t *ep, struct sockaddr_storage *ss) {
    memset(ss, 0, sizeof *ss);
    if (family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
        s->sin6_family = AF_INET6; s->sin6_port = htons(ep->port);
        if (ep->family == 6) {
            memcpy(&s->sin6_addr, ep->addr, 16);
        } else {
            uint8_t *a = s->sin6_addr.s6_addr;
            memset(a, 0, 10); a[10] = 0xff; a[11] = 0xff; memcpy(a + 12, ep->addr, 4);
        }
        return sizeof *s;
    }
    struct sockaddr_in *s = (struct sockaddr_in *)ss;
    s->sin_family = AF_INET; s->sin_port = htons(ep->port);
    memcpy(&s->sin_addr, ep->addr, 4);
    return sizeof *s;
}

/* Dual-stack UDP socket (IPv6 + IPv4 via v4-mapped). Returns -1 if IPv6 is
 * unavailable, so the caller can fall back to udp_bind_any(4, ...). */
int udp_bind_dual(uint16_t port, ep_t *bound) {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) { fprintf(stderr, "[net] socket(AF_INET6) failed: %s (falling back to IPv4-only)\n", strerror(errno)); return -1; }
    int off = 0; setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
    struct sockaddr_in6 s; memset(&s, 0, sizeof s);
    s.sin6_family = AF_INET6; s.sin6_addr = in6addr_any; s.sin6_port = htons(port);
    if (bind(fd, (struct sockaddr *)&s, sizeof s) != 0) {
        fprintf(stderr, "[net] bind([::]:%u) failed: %s (falling back to IPv4-only)\n", port, strerror(errno));
        close(fd); return -1;
    }
    struct sockaddr_storage ss; socklen_t bl = sizeof ss;
    getsockname(fd, (struct sockaddr *)&ss, &bl);
    if (bound) sockaddr_to_ep((struct sockaddr *)&ss, bound);
    return fd;
}
