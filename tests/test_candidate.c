#include "candidate.h"
#include "keys.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sodium.h>

static int cand_eq(const candidate_t *a, const candidate_t *b) {
    int alen = a->ep.family == 6 ? 16 : 4;
    return a->type == b->type
        && a->ep.family == b->ep.family
        && a->ep.port == b->ep.port
        && memcmp(a->ep.addr, b->ep.addr, alen) == 0;
}

int main(void) {
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    candidate_t cands[MAX_CANDS];
    int n = cand_collect_host(cands, MAX_CANDS);
    printf("host candidates (%d):\n", n);
    cand_print(cands, n);

    /* Fabricate a server-reflexive candidate (no real STUN in this env). */
    if (n < MAX_CANDS) {
        candidate_t *c = &cands[n++];
        c->type = CAND_SRFLX; c->ep.family = 4;
        memset(c->ep.addr, 0, 16);
        inet_pton(AF_INET, "203.0.113.7", c->ep.addr);
        c->ep.port = 41234;
    }
    printf("with srflx (%d):\n", n);
    cand_print(cands, n);

    /* serialize -> deserialize roundtrip */
    uint8_t wire[512];
    int wlen = cand_serialize(cands, n, wire, sizeof wire);
    if (wlen < 0) { fprintf(stderr, "serialize failed\n"); return 1; }
    candidate_t back[MAX_CANDS];
    int m = cand_deserialize(wire, wlen, back, MAX_CANDS);
    if (m != n) { fprintf(stderr, "roundtrip count mismatch (n=%d m=%d)\n", n, m); return 1; }
    for (int i = 0; i < n; i++)
        if (!cand_eq(&cands[i], &back[i])) { fprintf(stderr, "roundtrip field mismatch @%d\n", i); return 1; }
    printf("serialize roundtrip: OK (%d bytes on the wire)\n", wlen);

    /* K -> signaling subkey -> seal/open roundtrip */
    uint8_t K[32]; randombytes_buf(K, sizeof K);
    uint8_t sk[32]; derive_subkey(sk, SUBKEY_SIGNAL, K);

    uint8_t sealed[600]; size_t slen = 0;
    if (cand_seal(sk, wire, wlen, sealed, &slen) != 0) { fprintf(stderr,"seal failed\n"); return 1; }
    uint8_t opened[512]; size_t olen = 0;
    if (cand_open(sk, sealed, slen, opened, &olen) != 0) { fprintf(stderr,"open failed\n"); return 1; }
    if (olen != (size_t)wlen || memcmp(opened, wire, wlen) != 0) { fprintf(stderr, "seal/open mismatch\n"); return 1; }
    printf("seal/open roundtrip: OK (%d -> %zu bytes sealed)\n", wlen, slen);

    /* tamper detection */
    sealed[slen-1] ^= 0x01;
    if (cand_open(sk, sealed, slen, opened, &olen) == 0) { fprintf(stderr, "tamper NOT detected\n"); return 1; }
    printf("tamper detection: OK\n\nall tests passed.\n");
    return 0;
}
