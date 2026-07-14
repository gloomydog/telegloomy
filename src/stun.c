#include "stun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

#define STUN_BINDING_REQUEST 0x0001
#define STUN_BINDING_SUCCESS 0x0101
#define STUN_MAGIC_COOKIE    0x2112A442u
#define STUN_ATTR_XOR_MAPPED 0x0020
#define STUN_ATTR_MAPPED     0x0001

static void fill_random(unsigned char *p, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { if (fread(p,1,n,f)!=n) for (size_t i=0;i<n;i++) p[i]=rand()&0xff; fclose(f); return; }
    for (size_t i=0;i<n;i++) p[i]=rand()&0xff;
}

static int parse_mapped(const unsigned char *buf, ssize_t n, const unsigned char *txid, ep_t *out) {
    if (n < 20) return -1;
    unsigned mt=(buf[0]<<8)|buf[1], ml=(buf[2]<<8)|buf[3];
    if (mt!=STUN_BINDING_SUCCESS || memcmp(buf+8,txid,12)!=0) return -1;
    size_t off=20, endp=20+ml; if (endp>(size_t)n) endp=n;
    while (off+4<=endp) {
        unsigned at=(buf[off]<<8)|buf[off+1], al=(buf[off+2]<<8)|buf[off+3];
        size_t av=off+4; if (av+al>endp) break;
        if ((at==STUN_ATTR_XOR_MAPPED||at==STUN_ATTR_MAPPED)&&al>=8&&buf[av+1]==0x01) {
            unsigned rp=(buf[av+2]<<8)|buf[av+3];
            if (at==STUN_ATTR_XOR_MAPPED) {
                out->port = rp ^ (STUN_MAGIC_COOKIE>>16);
                out->addr[0]=buf[av+4]^((STUN_MAGIC_COOKIE>>24)&0xff);
                out->addr[1]=buf[av+5]^((STUN_MAGIC_COOKIE>>16)&0xff);
                out->addr[2]=buf[av+6]^((STUN_MAGIC_COOKIE>>8)&0xff);
                out->addr[3]=buf[av+7]^(STUN_MAGIC_COOKIE&0xff);
            } else { out->port=rp; memcpy(out->addr,buf+av+4,4); }
            out->family=4; return 0;
        }
        off = av + ((al+3)&~3u);
    }
    return -1;
}

int stun_query_on(int fd, const char *host, const char *port, ep_t *out) {
    /* Match the socket family: a dual-stack (AF_INET6) socket reaches an IPv4
     * STUN server via a v4-mapped address. */
    struct sockaddr_storage lss; socklen_t ll = sizeof lss;
    int fam = AF_INET;
    if (getsockname(fd, (struct sockaddr *)&lss, &ll) == 0) fam = lss.ss_family;

    struct addrinfo hints={0}, *res;
    hints.ai_socktype=SOCK_DGRAM;
    if (fam == AF_INET6) { hints.ai_family = AF_INET6; hints.ai_flags = AI_V4MAPPED | AI_ALL; }
    else                 { hints.ai_family = AF_INET; }
    if (getaddrinfo(host,port,&hints,&res)!=0) return -1;
    struct timeval tv={.tv_sec=2,.tv_usec=0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    unsigned char req[20];
    req[0]=(STUN_BINDING_REQUEST>>8)&0xff; req[1]=STUN_BINDING_REQUEST&0xff; req[2]=0; req[3]=0;
    req[4]=(STUN_MAGIC_COOKIE>>24)&0xff; req[5]=(STUN_MAGIC_COOKIE>>16)&0xff;
    req[6]=(STUN_MAGIC_COOKIE>>8)&0xff;  req[7]=STUN_MAGIC_COOKIE&0xff;
    fill_random(req+8,12);
    int rc=-1;
    if (sendto(fd,req,sizeof req,0,res->ai_addr,res->ai_addrlen)==(ssize_t)sizeof req) {
        unsigned char buf[512]; ssize_t n=recv(fd,buf,sizeof buf,0);
        rc = parse_mapped(buf,n,req+8,out);
    }
    freeaddrinfo(res);
    return rc;
}

int stun_query(const char *host, const char *port, ep_t *out) {
    int fd=socket(AF_INET,SOCK_DGRAM,0); if (fd<0) return -1;
    int rc=stun_query_on(fd,host,port,out);
    close(fd); return rc;
}

#include "net.h"
nat_type_t nat_detect(int fd, ep_t *mapped) {
    ep_t a, b; int ga, gb;
    ga = stun_query_on(fd, "stun.l.google.com",  "19302", &a) == 0;
    gb = stun_query_on(fd, "stun1.l.google.com", "19302", &b) == 0;
    if (ga && mapped) *mapped = a;
    else if (gb && mapped) *mapped = b;
    if (!ga && !gb) return NAT_UNKNOWN;
    if (ga && gb)  return ep_eq(&a, &b) ? NAT_CONE : NAT_SYMMETRIC;
    return NAT_UNKNOWN;
}
