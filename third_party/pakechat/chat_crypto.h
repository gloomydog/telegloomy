#ifndef CHAT_CRYPTO_H
#define CHAT_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <sodium.h>

#define CHAT_HEADERBYTES crypto_secretstream_xchacha20poly1305_HEADERBYTES /* 24 */
#define CHAT_ABYTES      crypto_secretstream_xchacha20poly1305_ABYTES      /* 17 */
#define CHAT_KEYBYTES    32

typedef struct {
    crypto_secretstream_xchacha20poly1305_state send_state;
    crypto_secretstream_xchacha20poly1305_state recv_state;
    uint8_t send_key[CHAT_KEYBYTES];
    uint8_t recv_key[CHAT_KEYBYTES];
    int handshake_done; /* has recv_state been init_pull'd yet? */
} chat_crypto_ctx;

/*
 * Derives per-direction keys from CPace's session_key and initializes our
 * own send stream. Send out_header (24 bytes) to the peer (the receive
 * stream can't be used yet at this point -- chat_crypto_finish_handshake
 * can't be called until the peer's header arrives).
 * Returns: 0 = success, -1 = failure
 */
int chat_crypto_start(chat_crypto_ctx *ctx,
                       const uint8_t session_key[CHAT_KEYBYTES],
                       int is_initiator,
                       uint8_t out_header[CHAT_HEADERBYTES]);

/*
 * Initializes the receive stream using the header that arrived from the
 * peer. chat_crypto_decrypt cannot be used until this has been called.
 * Returns: 0 = success, -1 = invalid header
 */
int chat_crypto_finish_handshake(chat_crypto_ctx *ctx, const uint8_t peer_header[CHAT_HEADERBYTES]);

/*
 * Encrypts a message. out_ct needs at least msg_len + CHAT_ABYTES bytes.
 * If is_final != 0, a stream-termination tag is set (used e.g. when
 * leaving a room). A send stream that has sent the termination tag can no
 * longer be used afterwards.
 * Returns: 0 = success, -1 = failure
 */
int chat_crypto_encrypt(chat_crypto_ctx *ctx,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t *out_ct, size_t *out_ct_len,
                         int is_final);

/*
 * Decrypts a received ciphertext. out_msg needs at least ct_len - CHAT_ABYTES
 * bytes. *out_is_final reports whether the received block carried the
 * termination tag.
 * Returns: 0 = success, -1 = tamper detection / out-of-order / other
 * failure (the session should be discarded in this case)
 */
int chat_crypto_decrypt(chat_crypto_ctx *ctx,
                         const uint8_t *ct, size_t ct_len,
                         uint8_t *out_msg, size_t *out_msg_len,
                         int *out_is_final);

/* Wipes key material from memory. */
void chat_crypto_wipe(chat_crypto_ctx *ctx);

/* Upper bound on a single message (plaintext). Plenty for chat use. */
#define CHAT_MAX_MSG_LEN 4096

/*
 * Encrypt-with-padding. The required size of out_ct can be computed ahead
 * of time with chat_crypto_encrypt_capacity(). Returns -1 if msg_len
 * exceeds CHAT_MAX_MSG_LEN.
 * Padding rounds the plaintext length up to a multiple of PAD_BLOCKSIZE,
 * making it harder to infer the exact character count of the original
 * message from the ciphertext size.
 */
int chat_crypto_encrypt_padded(chat_crypto_ctx *ctx,
                                const uint8_t *msg, size_t msg_len,
                                uint8_t *out_ct, size_t out_ct_cap, size_t *out_ct_len,
                                int is_final);

/* Returns the minimum number of bytes required for out_ct_cap. */
size_t chat_crypto_encrypt_capacity(size_t msg_len);

/*
 * Decrypt-with-padding. out_msg_cap of CHAT_MAX_MSG_LEN or more is recommended.
 * Returns: 0 = success, -1 = tampering / invalid padding / other failure
 */
int chat_crypto_decrypt_padded(chat_crypto_ctx *ctx,
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *out_msg, size_t out_msg_cap, size_t *out_msg_len,
                                int *out_is_final);

#endif
