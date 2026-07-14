#include "candidate.h"
#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>

static int is_v6_usable(const uint8_t a[16]) {
    static const uint8_t loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (memcmp(a, loop, 16) == 0) return 0;            /* ::1        */
    if (a[0]==0xfe && (a[1]&0xc0)==0x80) return 0;     /* fe80::/10  */
    int allzero = 1; for (int i=0;i<16;i++) if (a[i]) { allzero=0; break; }
    return !allzero;                                    /* ::         */
}

int cand_collect_host(candidate_t *out, int max) {
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) != 0) return 0;
    int n = 0;
    for (p = ifa; p && n < max; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        if (p->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)p->ifa_addr;
            uint32_t h = ntohl(s->sin_addr.s_addr);
            if ((h >> 24) == 127) continue;             /* 127/8 */
            out[n].type = CAND_HOST;
            out[n].ep.family = 4;
            memset(out[n].ep.addr, 0, 16);
            memcpy(out[n].ep.addr, &s->sin_addr.s_addr, 4);
            out[n].ep.port = 0;                          /* filled after bind */
            n++;
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)p->ifa_addr;
            if (!is_v6_usable(s->sin6_addr.s6_addr)) continue;
            out[n].type = CAND_HOST;
            out[n].ep.family = 6;
            memcpy(out[n].ep.addr, s->sin6_addr.s6_addr, 16);
            out[n].ep.port = 0;
            n++;
        }
    }
    freeifaddrs(ifa);
    return n;
}

int cand_serialize(const candidate_t *c, int n, uint8_t *buf, size_t bufsz) {
    size_t off = 0;
    if (bufsz < 1) return -1;
    buf[off++] = (uint8_t)n;
    for (int i = 0; i < n; i++) {
        int alen = c[i].ep.family == 6 ? 16 : 4;
        if (off + 4 + (size_t)alen > bufsz) return -1;
        buf[off++] = c[i].type;
        buf[off++] = c[i].ep.family;
        buf[off++] = (c[i].ep.port >> 8) & 0xff;
        buf[off++] = c[i].ep.port & 0xff;
        memcpy(buf + off, c[i].ep.addr, alen);
        off += alen;
    }
    return (int)off;
}

int cand_deserialize(const uint8_t *buf, size_t len, candidate_t *out, int max) {
    if (len < 1) return -1;
    int n = buf[0]; size_t off = 1;
    if (n > max) return -1;
    for (int i = 0; i < n; i++) {
        if (off + 4 > len) return -1;
        out[i].type = buf[off++];
        out[i].ep.family = buf[off++];
        int alen = out[i].ep.family == 6 ? 16 : 4;
        out[i].ep.port = (uint16_t)((buf[off] << 8) | buf[off+1]); off += 2;
        if (off + (size_t)alen > len) return -1;
        memset(out[i].ep.addr, 0, 16);
        memcpy(out[i].ep.addr, buf + off, alen);
        off += alen;
    }
    return n;
}

int cand_seal(const uint8_t sk[32], const uint8_t *pt, size_t ptlen,
              uint8_t *out, size_t *outlen) {
    unsigned char *nonce = out;
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    unsigned long long clen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, &clen,
            pt, ptlen, NULL, 0, NULL, nonce, sk) != 0) return -1;
    *outlen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen;
    return 0;
}

int cand_open(const uint8_t sk[32], const uint8_t *ct, size_t ctlen,
              uint8_t *out, size_t *outlen) {
    const size_t NB = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (ctlen < NB + crypto_aead_xchacha20poly1305_ietf_ABYTES) return -1;
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out, &mlen, NULL, ct + NB, ctlen - NB, NULL, 0, ct, sk) != 0) return -1;
    *outlen = mlen;
    return 0;
}

void cand_print(const candidate_t *c, int n) {
    char s[INET6_ADDRSTRLEN];
    for (int i = 0; i < n; i++) {
        int af = c[i].ep.family == 6 ? AF_INET6 : AF_INET;
        inet_ntop(af, c[i].ep.addr, s, sizeof s);
        printf("  [%s] %s%s%s:%u\n",
               c[i].type == CAND_SRFLX ? "srflx" : "host ",
               af == AF_INET6 ? "[" : "", s, af == AF_INET6 ? "]" : "",
               c[i].ep.port);
    }
}
