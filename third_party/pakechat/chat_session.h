#ifndef CHAT_SESSION_H
#define CHAT_SESSION_H

#include "cpace.h"
#include "chat_crypto.h"

typedef enum {
    SESSION_IDLE,             /* not started */
    SESSION_WAIT_PEER_POINT,  /* sent our CPace round 1, waiting for peer's Y */
    SESSION_WAIT_CONFIRM,     /* session_key derived, waiting for peer's confirmation MAC */
    SESSION_WAIT_HEADER,      /* confirmation OK, waiting for peer's secretstream header */
    SESSION_ACTIVE,           /* encrypted chat available */
    SESSION_BROKEN,           /* should be discarded due to tamper detection / confirmation failure / etc. */
    SESSION_CLOSED            /* ended normally after sending/receiving the FINAL tag */
} session_state_t;

#define ROOM_CODE_MAXLEN 32
#define ROOM_ID_MAXLEN   64

typedef struct {
    session_state_t state;
    cpace_ctx cpace;
    chat_crypto_ctx crypto;
    int is_initiator;
    char room_code[ROOM_CODE_MAXLEN];
    size_t room_code_len;
    char room_id[ROOM_ID_MAXLEN];
    size_t room_id_len;
    uint8_t my_header[CHAT_HEADERBYTES]; /* header to send to the peer (generated while WAIT_HEADER) */
} chat_session;

/* Starts a session. On success, send session->cpace.my_point (32 bytes) to the peer.
 * Returns: 0 = success, -1 = room_code/room_id too long, etc. */
int session_begin(chat_session *s,
                   const char *room_code, size_t room_code_len,
                   const char *room_id, size_t room_id_len,
                   int is_initiator);

/* Receives the peer's CPace public point and derives session_key.
 * On success, compute the confirmation MAC with
 * cpace_compute_confirmation(&s->cpace, <our role>, mac) and send it to the peer.
 * Returns: 0 = success, -1 = invalid point (transitions to state = BROKEN) */
int session_on_peer_point(chat_session *s, const uint8_t peer_point[CPACE_POINTBYTES]);

/* Verifies the confirmation MAC received from the peer. role_expected is the
 * peer's role ("B" if we're the initiator so the peer is the responder, etc).
 * On success, send session->my_header to the peer.
 * Returns: 0 = success (state -> WAIT_HEADER), -1 = MAC mismatch (state -> BROKEN,
 * suspected impersonation / typo) */
int session_on_peer_confirm(chat_session *s, const char *role_expected,
                             const uint8_t peer_mac[CPACE_MACBYTES]);

/* Receives the peer's secretstream header and initializes the receive stream.
 * Returns: 0 = success (state -> ACTIVE), -1 = failure */
int session_on_peer_header(chat_session *s, const uint8_t peer_header[CHAT_HEADERBYTES]);

/* Only usable when state==ACTIVE. Encrypts with padding included. */
int session_encrypt(chat_session *s, const uint8_t *msg, size_t msg_len,
                     uint8_t *out_ct, size_t out_ct_cap, size_t *out_ct_len, int is_final);

/* Only usable when state==ACTIVE. On decryption failure the state
 * automatically transitions to BROKEN.
 * Transitions to state=CLOSED upon receiving is_final. */
int session_decrypt(chat_session *s, const uint8_t *ct, size_t ct_len,
                     uint8_t *out_msg, size_t out_msg_cap, size_t *out_msg_len, int *out_is_final);

/*
 * Reconnects from a BROKEN state. Rebuilds all key material from scratch
 * using the same room_code/room_id (CPace uses a fresh random scalar each
 * time it's called, so even with the same room_code, we arrive at a
 * completely different session key each time -- a fresh key agreement
 * unrelated to the previous corruption).
 * After calling this, the state is as if session_begin had just been
 * called again (WAIT_PEER_POINT); the new session->cpace.my_point must be
 * sent to the peer.
 * Returns: 0 = success, -1 = state != BROKEN (misuse guard)
 */
int session_reconnect(chat_session *s);

/* Wipes all state, including key material (call this when the chat ends). */
void session_wipe(chat_session *s);

#endif
