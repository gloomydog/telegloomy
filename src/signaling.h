#pragma once
#include <stdint.h>
#include <stddef.h>

/* Nostr + CPace signaling over MULTIPLE relays simultaneously (fan-out
 * publish, fan-in receive), so a single relay outage doesn't block rendezvous.
 * One passphrase drives: rendezvous tag, CPace PAKE, sealed candidate exchange. */
typedef struct signaling signaling_t;

/* relay: a single "host"/"wss://host[:port]" tried first, or NULL. Built-in
 * public relays are always added as fallbacks. is_initiator: 1 = CPace role A. */
signaling_t *signaling_open(const char *relay, const char *passphrase, int is_initiator);

int  signaling_derive_key(signaling_t *s, uint8_t K[32]);   /* blocks until handshake done */

int  signaling_send(signaling_t *s, const uint8_t *blob, size_t len);            /* to all relays */
int  signaling_recv(signaling_t *s, uint8_t *buf, size_t cap, size_t *len);      /* blocking */
int  signaling_try_recv(signaling_t *s, uint8_t *buf, size_t cap, size_t *len);  /* nonblocking: -1 if none */

void signaling_close(signaling_t *s);
