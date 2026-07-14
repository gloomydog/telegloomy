#pragma once
#include <stdint.h>
#include <sodium.h>

/* Subkey ids derived from the PAKE master key K (from CPace, ported from
 * pakechat). One passphrase -> K -> every channel key below. */
enum {
    SUBKEY_SIGNAL    = 1,  /* seal candidate exchange sent over Nostr        */
    SUBKEY_REL_A2B   = 2,  /* reliable stream: initiator  -> responder       */
    SUBKEY_REL_B2A   = 3,  /* reliable stream: responder  -> initiator       */
    SUBKEY_UNREL_A2B = 4,  /* datagrams (voice): initiator -> responder      */
    SUBKEY_UNREL_B2A = 5,  /* datagrams (voice): responder -> initiator      */
    SUBKEY_PUNCH     = 6,  /* authenticate hole-punch PING/PONG              */
};

/* Derive a 32-byte subkey from the 32-byte master K. */
void derive_subkey(uint8_t out[32], uint64_t id, const uint8_t K[32]);
