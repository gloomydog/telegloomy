#include "stun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sodium.h>

#define STUN_BINDING_REQUEST 0x0001
#define STUN_BINDING_SUCCESS 0x0101
#define STUN_MAGIC_COOKIE    0x2112A442u
#define STUN_ATTR_XOR_MAPPED 0x0020
#define STUN_ATTR_MAPPED     0x0001

/* STUN transaction ids must be unpredictable so an off-path attacker can't spoof
 * a Binding response. Use libsodium's CSPRNG (self-seeding) rather than a
 * best-effort /dev/urandom read that silently fell back to unseeded rand(). */
static void fill_random(unsigned char *p, size_t n) {
    randombytes_buf(p, n);
}

/* Parse (XOR-)MAPPED-ADDRESS for either family. IPv4 (family byte 0x01) yields a
 * 4-byte address; IPv6 (0x02) a 16-byte one. For XOR-MAPPED the port and the
 * first 4 address bytes are XORed with the magic cookie; the remaining 12 IPv6
 * bytes are XORed with the transaction id (RFC 5389 15.2). */
static int parse_mapped(const unsigned char *buf, ssize_t n, const unsigned char *txid, ep_t *out) {
    if (n < 20) return -1;
    unsigned mt=(buf[0]<<8)|buf[1], ml=(buf[2]<<8)|buf[3];
    if (mt!=STUN_BINDING_SUCCESS || memcmp(buf+8,txid,12)!=0) return -1;
    size_t off=20, endp=20+ml; if (endp>(size_t)n) endp=n;
    while (off+4<=endp) {
        unsigned at=(buf[off]<<8)|buf[off+1], al=(buf[off+2]<<8)|buf[off+3];
        size_t av=off+4; if (av+al>endp) break;
        int is_mapped = (at==STUN_ATTR_XOR_MAPPED || at==STUN_ATTR_MAPPED);
        unsigned fam = (is_mapped && al>=2) ? buf[av+1] : 0;
        if (fam==0x01 && al>=8) {                                  /* IPv4 */
            unsigned rp=(buf[av+2]<<8)|buf[av+3];
            if (at==STUN_ATTR_XOR_MAPPED) {
                out->port = rp ^ (STUN_MAGIC_COOKIE>>16);
                out->addr[0]=buf[av+4]^((STUN_MAGIC_COOKIE>>24)&0xff);
                out->addr[1]=buf[av+5]^((STUN_MAGIC_COOKIE>>16)&0xff);
                out->addr[2]=buf[av+6]^((STUN_MAGIC_COOKIE>>8)&0xff);
                out->addr[3]=buf[av+7]^(STUN_MAGIC_COOKIE&0xff);
            } else { out->port=rp; memcpy(out->addr,buf+av+4,4); }
            memset(out->addr+4, 0, 12);
            out->family=4; return 0;
        }
        if (fam==0x02 && al>=20) {                                 /* IPv6 */
            unsigned rp=(buf[av+2]<<8)|buf[av+3];
            if (at==STUN_ATTR_XOR_MAPPED) {
                out->port = rp ^ (STUN_MAGIC_COOKIE>>16);
                out->addr[0]=buf[av+4]^((STUN_MAGIC_COOKIE>>24)&0xff);
                out->addr[1]=buf[av+5]^((STUN_MAGIC_COOKIE>>16)&0xff);
                out->addr[2]=buf[av+6]^((STUN_MAGIC_COOKIE>>8)&0xff);
                out->addr[3]=buf[av+7]^(STUN_MAGIC_COOKIE&0xff);
                for (int i=0;i<12;i++) out->addr[4+i]=buf[av+8+i]^txid[i];
            } else { out->port=rp; memcpy(out->addr,buf+av+4,16); }
            out->family=6; return 0;
        }
        off = av + ((al+3)&~3u);
    }
    return -1;
}

/* Issue a Binding Request over a chosen destination family and return the srflx
 * of that family. dst_af == AF_INET learns the IPv4 mapping (reached v4-mapped
 * on a dual-stack socket); AF_INET6 learns the real IPv6 srflx -- i.e. the exact
 * global v6 address the kernel sources from toward the internet, which is what a
 * peer must target and we must send from for v6 hole punching to line up. A
 * v4-only socket cannot service an AF_INET6 request. */
static int stun_query_af(int fd, int dst_af, const char *host, const char *port, ep_t *out) {
    struct sockaddr_storage lss; socklen_t ll = sizeof lss;
    int sockfam = AF_INET;
    if (getsockname(fd, (struct sockaddr *)&lss, &ll) == 0) sockfam = lss.ss_family;
    if (dst_af == AF_INET6 && sockfam != AF_INET6) return -1;

    struct addrinfo hints={0}, *res;
    hints.ai_socktype=SOCK_DGRAM;
    if (dst_af == AF_INET6)      { hints.ai_family = AF_INET6; }                            /* real AAAA only */
    else if (sockfam == AF_INET6){ hints.ai_family = AF_INET6; hints.ai_flags = AI_V4MAPPED | AI_ALL; }
    else                         { hints.ai_family = AF_INET; }
    if (getaddrinfo(host,port,&hints,&res)!=0) return -1;

    /* Pick a resolved address of the family we actually want to probe: a real v6
     * for AF_INET6, else a v4 (or v4-mapped) for AF_INET. */
    struct addrinfo *pick=NULL;
    for (struct addrinfo *ai=res; ai; ai=ai->ai_next) {
        if (dst_af == AF_INET6) {
            if (ai->ai_family==AF_INET6 &&
                !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)ai->ai_addr)->sin6_addr)) { pick=ai; break; }
        } else {
            if (ai->ai_family==AF_INET) { pick=ai; break; }
            if (ai->ai_family==AF_INET6 &&
                IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)ai->ai_addr)->sin6_addr)) { pick=ai; break; }
        }
    }
    if (!pick) { freeaddrinfo(res); return -1; }

    struct timeval tv={.tv_sec=2,.tv_usec=0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    unsigned char req[20];
    req[0]=(STUN_BINDING_REQUEST>>8)&0xff; req[1]=STUN_BINDING_REQUEST&0xff; req[2]=0; req[3]=0;
    req[4]=(STUN_MAGIC_COOKIE>>24)&0xff; req[5]=(STUN_MAGIC_COOKIE>>16)&0xff;
    req[6]=(STUN_MAGIC_COOKIE>>8)&0xff;  req[7]=STUN_MAGIC_COOKIE&0xff;
    fill_random(req+8,12);
    int rc=-1;
    if (sendto(fd,req,sizeof req,0,pick->ai_addr,pick->ai_addrlen)==(ssize_t)sizeof req) {
        unsigned char buf[512]; ssize_t n=recv(fd,buf,sizeof buf,0);
        rc = parse_mapped(buf,n,req+8,out);
    }
    freeaddrinfo(res);
    return rc;
}

int stun_query_on(int fd, const char *host, const char *port, ep_t *out) {
    return stun_query_af(fd, AF_INET, host, port, out);
}

int stun_query6_on(int fd, const char *host, const char *port, ep_t *out) {
    return stun_query_af(fd, AF_INET6, host, port, out);
}

/* ------------------------------ server list ----------------------------- */

/* Spread across operators on purpose: nat_detect probes the first two that
 * answer, and two probes to one provider share its failure and its blocking.
 * Ports vary (19302 / 3478 / 443) which also helps on restrictive networks. */
static const char *DEFAULT_SERVERS[] = {
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun1.l.google.com:19302",
    "stun.nextcloud.com:443",
};

static char g_host[STUN_MAX_SERVERS][160];
static char g_port[STUN_MAX_SERVERS][8];
static int  g_nsrv = 0;
static int  g_parsed = 0;

/* Accepts "host", "host:port", "[v6::literal]" and "[v6::literal]:port".
 * A bare (unbracketed) IPv6 literal is taken as a host with no port, since its
 * colons are part of the address. Silently ignores entries it can't use. */
static void add_server(const char *spec) {
    if (g_nsrv >= STUN_MAX_SERVERS) return;
    char tmp[160];
    snprintf(tmp, sizeof tmp, "%s", spec);
    char *host = tmp, *port = NULL;
    if (*host == '[') {
        char *close = strchr(host, ']');
        if (!close) return;                          /* unterminated bracket */
        *close = 0; host++;
        if (close[1] == ':' && close[2]) port = close + 2;
    } else {
        char *last = strrchr(host, ':');
        /* Only a single colon can be a port separator; several means a bare
         * IPv6 literal, which cannot carry one. */
        if (last && strchr(host, ':') == last) { *last = 0; port = last + 1; }
    }
    if (!*host) return;
    snprintf(g_host[g_nsrv], sizeof g_host[0], "%s", host);
    snprintf(g_port[g_nsrv], sizeof g_port[0], "%s", (port && *port) ? port : "3478");
    g_nsrv++;
}

static void parse_servers(void) {
    if (g_parsed) return;
    g_parsed = 1;
    const char *env = getenv("STUN_SERVERS");
    if (env && *env) {
        char buf[1024], *save = NULL;
        snprintf(buf, sizeof buf, "%s", env);
        for (char *tok = strtok_r(buf, ", \t", &save); tok; tok = strtok_r(NULL, ", \t", &save))
            add_server(tok);
    }
    if (g_nsrv == 0)              /* unset, empty, or every entry unparseable */
        for (unsigned i = 0; i < sizeof DEFAULT_SERVERS / sizeof DEFAULT_SERVERS[0]; i++)
            add_server(DEFAULT_SERVERS[i]);
}

int         stun_server_count(void)      { parse_servers(); return g_nsrv; }
const char *stun_server_host(int i)      { parse_servers(); return (i>=0 && i<g_nsrv) ? g_host[i] : NULL; }
const char *stun_server_port(int i)      { parse_servers(); return (i>=0 && i<g_nsrv) ? g_port[i] : NULL; }

/* Try each configured server in turn; first answer wins. */
static int stun_srflx_af(int fd, int dst_af, ep_t *out) {
    int n = stun_server_count();
    for (int i = 0; i < n; i++)
        if (stun_query_af(fd, dst_af, g_host[i], g_port[i], out) == 0) return 0;
    return -1;
}
int stun_srflx (int fd, ep_t *out) { return stun_srflx_af(fd, AF_INET,  out); }
int stun_srflx6(int fd, ep_t *out) { return stun_srflx_af(fd, AF_INET6, out); }

#include "net.h"
nat_type_t nat_detect(int fd, ep_t *mapped) {
    /* Take the first TWO servers that actually answer, rather than fixed slots:
     * a dead first entry would otherwise cost us the comparison entirely. */
    int n = stun_server_count();
    ep_t got[2]; int ngot = 0;
    for (int i = 0; i < n && ngot < 2; i++)
        if (stun_query_on(fd, g_host[i], g_port[i], &got[ngot]) == 0) ngot++;
    if (ngot == 0) return NAT_UNKNOWN;
    if (mapped) *mapped = got[0];
    if (ngot < 2) return NAT_UNKNOWN;      /* one datapoint cannot tell them apart */
    return ep_eq(&got[0], &got[1]) ? NAT_CONE : NAT_SYMMETRIC;
}
