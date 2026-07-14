#pragma once
#include "common.h"

#define MAX_CANDS 16

/* Gather local host candidates (non-loopback IPv4 + global IPv6). */
int  cand_collect_host(candidate_t *out, int max);

/* Wire format (per candidate): type(1) family(1) port_be(2) addr(4|16). */
int  cand_serialize(const candidate_t *c, int n, uint8_t *buf, size_t bufsz);
int  cand_deserialize(const uint8_t *buf, size_t len, candidate_t *out, int max);

/* AEAD (XChaCha20-Poly1305). out layout: nonce(24) || ciphertext || mac(16).
 * out needs ptlen + 40 bytes. Returns 0 on success. */
int  cand_seal(const uint8_t sk[32], const uint8_t *pt, size_t ptlen,
               uint8_t *out, size_t *outlen);
int  cand_open(const uint8_t sk[32], const uint8_t *ct, size_t ctlen,
               uint8_t *out, size_t *outlen);

void cand_print(const candidate_t *c, int n);
