#include "chat_crypto.h"
#include "padding.h"
#include <string.h>

#define DSI_A2B "PakeChat-v1-A2B"
#define DSI_B2A "PakeChat-v1-B2A"

/* Hashes the direction label keyed by session_key to derive separate
 * send/receive keys. */
static void derive_direction_keys(const uint8_t session_key[CHAT_KEYBYTES],
                                   uint8_t key_a2b[CHAT_KEYBYTES],
                                   uint8_t key_b2a[CHAT_KEYBYTES])
{
    crypto_generichash_state st;

    crypto_generichash_init(&st, session_key, CHAT_KEYBYTES, CHAT_KEYBYTES);
    crypto_generichash_update(&st, (const uint8_t *)DSI_A2B, strlen(DSI_A2B));
    crypto_generichash_final(&st, key_a2b, CHAT_KEYBYTES);

    crypto_generichash_init(&st, session_key, CHAT_KEYBYTES, CHAT_KEYBYTES);
    crypto_generichash_update(&st, (const uint8_t *)DSI_B2A, strlen(DSI_B2A));
    crypto_generichash_final(&st, key_b2a, CHAT_KEYBYTES);
}

int chat_crypto_start(chat_crypto_ctx *ctx,
                       const uint8_t session_key[CHAT_KEYBYTES],
                       int is_initiator,
                       uint8_t out_header[CHAT_HEADERBYTES])
{
    uint8_t key_a2b[CHAT_KEYBYTES], key_b2a[CHAT_KEYBYTES];

    if (sodium_init() < 0) return -1;
    memset(ctx, 0, sizeof(*ctx));

    derive_direction_keys(session_key, key_a2b, key_b2a);

    if (is_initiator) {
        memcpy(ctx->send_key, key_a2b, CHAT_KEYBYTES);
        memcpy(ctx->recv_key, key_b2a, CHAT_KEYBYTES);
    } else {
        memcpy(ctx->send_key, key_b2a, CHAT_KEYBYTES);
        memcpy(ctx->recv_key, key_a2b, CHAT_KEYBYTES);
    }
    sodium_memzero(key_a2b, sizeof(key_a2b));
    sodium_memzero(key_b2a, sizeof(key_b2a));

    if (crypto_secretstream_xchacha20poly1305_init_push(&ctx->send_state, out_header, ctx->send_key) != 0)
        return -1;

    ctx->handshake_done = 0;
    return 0;
}

int chat_crypto_finish_handshake(chat_crypto_ctx *ctx, const uint8_t peer_header[CHAT_HEADERBYTES])
{
    if (crypto_secretstream_xchacha20poly1305_init_pull(&ctx->recv_state, peer_header, ctx->recv_key) != 0)
        return -1;
    ctx->handshake_done = 1;
    return 0;
}

int chat_crypto_encrypt(chat_crypto_ctx *ctx,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t *out_ct, size_t *out_ct_len,
                         int is_final)
{
    unsigned char tag = is_final
        ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    unsigned long long ct_len;

    if (crypto_secretstream_xchacha20poly1305_push(&ctx->send_state,
            out_ct, &ct_len, msg, msg_len, NULL, 0, tag) != 0)
        return -1;

    *out_ct_len = (size_t)ct_len;
    return 0;
}

int chat_crypto_decrypt(chat_crypto_ctx *ctx,
                         const uint8_t *ct, size_t ct_len,
                         uint8_t *out_msg, size_t *out_msg_len,
                         int *out_is_final)
{
    unsigned char tag;
    unsigned long long msg_len;

    if (!ctx->handshake_done) return -1;

    /* If push fails (tampering detected / invalid data), always return -1
     * so the caller discards the session. Never retry or partially
     * accept here. */
    if (crypto_secretstream_xchacha20poly1305_pull(&ctx->recv_state,
            out_msg, &msg_len, &tag, ct, ct_len, NULL, 0) != 0)
        return -1;

    *out_msg_len = (size_t)msg_len;
    *out_is_final = (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    return 0;
}

void chat_crypto_wipe(chat_crypto_ctx *ctx)
{
    sodium_memzero(ctx, sizeof(*ctx));
}

size_t chat_crypto_encrypt_capacity(size_t msg_len)
{
    return pad_calc_capacity(msg_len) + CHAT_ABYTES;
}

int chat_crypto_encrypt_padded(chat_crypto_ctx *ctx,
                                const uint8_t *msg, size_t msg_len,
                                uint8_t *out_ct, size_t out_ct_cap, size_t *out_ct_len,
                                int is_final)
{
    uint8_t padbuf[CHAT_MAX_MSG_LEN + PAD_BLOCKSIZE];
    size_t padded_len;
    size_t pad_cap = pad_calc_capacity(msg_len);

    if (msg_len > CHAT_MAX_MSG_LEN) return -1;
    if (out_ct_cap < pad_cap + CHAT_ABYTES) return -1;

    if (pad_message(msg, msg_len, padbuf, sizeof(padbuf), &padded_len) != 0)
        return -1;

    int rc = chat_crypto_encrypt(ctx, padbuf, padded_len, out_ct, out_ct_len, is_final);
    sodium_memzero(padbuf, sizeof(padbuf));
    return rc;
}

int chat_crypto_decrypt_padded(chat_crypto_ctx *ctx,
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *out_msg, size_t out_msg_cap, size_t *out_msg_len,
                                int *out_is_final)
{
    uint8_t padbuf[CHAT_MAX_MSG_LEN + PAD_BLOCKSIZE];
    size_t padded_len, msg_len;

    if (ct_len > sizeof(padbuf)) return -1;

    if (chat_crypto_decrypt(ctx, ct, ct_len, padbuf, &padded_len, out_is_final) != 0)
        return -1;

    if (unpad_message(padbuf, padded_len, &msg_len) != 0) {
        sodium_memzero(padbuf, sizeof(padbuf));
        return -1; /* invalid padding = treat as tampering */
    }

    if (msg_len > out_msg_cap) {
        sodium_memzero(padbuf, sizeof(padbuf));
        return -1;
    }

    memcpy(out_msg, padbuf, msg_len);
    *out_msg_len = msg_len;
    sodium_memzero(padbuf, sizeof(padbuf));
    return 0;
}
