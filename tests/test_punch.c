#include "punch.h"
#include "net.h"
#include "keys.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sodium.h>

static void *runner(void *arg) {
    ep_t chosen;
    int rc = punch_run((punch_ctx *)arg, 3000, &chosen);
    return (void *)(long)rc;
}

/* Variant that also reports the confirmed endpoint, to check it is the peer's
 * ACTUAL source and not whatever candidate was advertised. */
struct srun { punch_ctx *c; int rc; ep_t chosen; };
static void *runner_ep(void *arg) {
    struct srun *s = arg;
    s->rc = punch_run(s->c, 3000, &s->chosen);
    return NULL;
}

int main(void) {
    if (sodium_init() < 0) return 1;

    ep_t ep_a, ep_b;
    int fda = udp_bind(4, &ep_a);
    int fdb = udp_bind(4, &ep_b);
    if (fda < 0 || fdb < 0) { fprintf(stderr, "bind failed\n"); return 1; }
    printf("peer A on 127.0.0.1:%u\npeer B on 127.0.0.1:%u\n", ep_a.port, ep_b.port);

    uint8_t K[32]; randombytes_buf(K, sizeof K);       /* same master both sides */
    uint8_t pk[32]; derive_subkey(pk, SUBKEY_PUNCH, K);

    punch_ctx a = { .fd = fda, .nremote = 1 };
    punch_ctx b = { .fd = fdb, .nremote = 1 };
    memcpy(a.key, pk, 32); memcpy(b.key, pk, 32);
    a.remote[0] = ep_b;                                /* A probes B */
    b.remote[0] = ep_a;                                /* B probes A */

    pthread_t ta, tb; void *ra, *rb;
    pthread_create(&ta, NULL, runner, &a);
    pthread_create(&tb, NULL, runner, &b);
    pthread_join(ta, &ra); pthread_join(tb, &rb);
    if ((long)ra == 0 && (long)rb == 0) printf("both paths confirmed: OK\n");
    else { fprintf(stderr, "punch failed (a=%ld b=%ld)\n", (long)ra, (long)rb); return 1; }

    /* Negative test: mismatched keys must NOT confirm a path. */
    ep_t ep_c, ep_d;
    int fdc = udp_bind(4, &ep_c), fdd = udp_bind(4, &ep_d);
    uint8_t wrong[32]; randombytes_buf(wrong, sizeof wrong);
    punch_ctx c = { .fd = fdc, .nremote = 1 }, d = { .fd = fdd, .nremote = 1 };
    memcpy(c.key, pk, 32); memcpy(d.key, wrong, 32);
    c.remote[0] = ep_d; d.remote[0] = ep_c;
    pthread_t tc, td; void *rc, *rd;
    pthread_create(&tc, NULL, runner, &c);
    pthread_create(&td, NULL, runner, &d);
    pthread_join(tc, &rc); pthread_join(td, &rd);
    if ((long)rc == -1 && (long)rd == -1) printf("key-mismatch rejected: OK\n");
    else { fprintf(stderr, "SECURITY: mismatched keys confirmed (c=%ld d=%ld)\n", (long)rc, (long)rd); return 1; }

    /* Actual-source test (the carrier-NAT fix): E advertises a WRONG address
     * for F, so E's own probes go nowhere. F probes E correctly. E must still
     * confirm -- on the address F's packets actually arrive from, not on the
     * bogus candidate it was handed. */
    ep_t ep_e, ep_f;
    int fde = udp_bind(4, &ep_e), fdf = udp_bind(4, &ep_f);
    if (fde < 0 || fdf < 0) { fprintf(stderr, "bind failed\n"); return 1; }
    punch_ctx e = { .fd = fde, .nremote = 1 }, f = { .fd = fdf, .nremote = 1 };
    memcpy(e.key, pk, 32); memcpy(f.key, pk, 32);
    e.remote[0] = ep_f; e.remote[0].port = 9;   /* wrong port: discard, nothing answers */
    f.remote[0] = ep_e;                          /* F probes E for real            */
    struct srun se = { .c = &e }, sf = { .c = &f };
    pthread_t te, tf;
    pthread_create(&te, NULL, runner_ep, &se);
    pthread_create(&tf, NULL, runner_ep, &sf);
    pthread_join(te, NULL); pthread_join(tf, NULL);
    if (se.rc != 0 || sf.rc != 0) { fprintf(stderr, "actual-source: path not confirmed (e=%d f=%d)\n", se.rc, sf.rc); return 1; }
    if (!ep_eq(&se.chosen, &ep_f))
        { fprintf(stderr, "actual-source: E confirmed the advertised bogus port, not F's real source\n"); return 1; }
    printf("actual-source confirmation: OK\n");

    printf("\nall tests passed.\n");
    return 0;
}
