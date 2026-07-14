#pragma once
#include "common.h"
#include "keys.h"
#include <stdint.h>
#include <stddef.h>

#define TR_MAXMSG 1024
#define TR_WIN    64

typedef void (*tr_recv_cb)(void *user, const uint8_t *data, size_t len);
/* Alternate datapath: send an on-wire packet somewhere other than the socket. */
typedef int  (*tr_send_fn)(void *user, const uint8_t *wire, size_t len);

typedef struct transport transport_t;

/* role: 0 = initiator (A), 1 = responder (B) — selects tx/rx subkeys.
 * fd must be a UDP socket already connect()ed to the peer (see punch). */
transport_t *transport_new(int fd, int role, const uint8_t K[32],
                           tr_recv_cb on_reliable, tr_recv_cb on_unreliable, void *user);
void transport_free(transport_t *t);

int  transport_send_reliable(transport_t *t, const uint8_t *data, size_t len);   /* -1 if window full */
int  transport_send_unreliable(transport_t *t, const uint8_t *data, size_t len); /* fire and forget   */

void transport_poll(transport_t *t, int timeout_ms);   /* recv, deliver, ack, retransmit */
int  transport_reliable_inflight(transport_t *t);       /* unacked count (for draining)   */
void transport_set_drop(transport_t *t, int pct);       /* debug: drop % of OUTGOING pkts */

/* Rebind delivery callbacks (used by the app layer to demux reliable msgs). */
void transport_set_callbacks(transport_t *t, tr_recv_cb rel, tr_recv_cb unrel, void *user);

/* Route unreliable (datagram/voice) delivery to a separate callback+user,
 * so reliable->app and unreliable->voice can have distinct owners. */
void transport_set_unreliable_cb(transport_t *t, tr_recv_cb unrel, void *user);

/* Route outbound packets through a relay (e.g. over Nostr) instead of the UDP
 * socket, and feed inbound relayed packets back in via transport_inject. */
void transport_set_relay(transport_t *t, tr_send_fn fn, void *user);
void transport_inject(transport_t *t, const uint8_t *wire, size_t len);
