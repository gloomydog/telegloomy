#include "chat_session.h"
#include <string.h>
#include <sodium.h>

int session_begin(chat_session *s,
                   const char *room_code, size_t room_code_len,
                   const char *room_id, size_t room_id_len,
                   int is_initiator)
{
    if (room_code_len >= ROOM_CODE_MAXLEN || room_id_len >= ROOM_ID_MAXLEN)
        return -1;

    memset(s, 0, sizeof(*s));
    memcpy(s->room_code, room_code, room_code_len);
    s->room_code_len = room_code_len;
    memcpy(s->room_id, room_id, room_id_len);
    s->room_id_len = room_id_len;
    s->is_initiator = is_initiator;

    if (cpace_init(&s->cpace, s->room_code, s->room_code_len,
                    s->room_id, s->room_id_len, is_initiator) != 0) {
        s->state = SESSION_BROKEN;
        return -1;
    }

    s->state = SESSION_WAIT_PEER_POINT;
    return 0;
}

int session_on_peer_point(chat_session *s, const uint8_t peer_point[CPACE_POINTBYTES])
{
    if (s->state != SESSION_WAIT_PEER_POINT) return -1;

    if (cpace_derive_session_key(&s->cpace, peer_point) != 0) {
        s->state = SESSION_BROKEN;
        return -1;
    }

    s->state = SESSION_WAIT_CONFIRM;
    return 0;
}

int session_on_peer_confirm(chat_session *s, const char *role_expected,
                             const uint8_t peer_mac[CPACE_MACBYTES])
{
    uint8_t expected_mac[CPACE_MACBYTES];

    if (s->state != SESSION_WAIT_CONFIRM) return -1;

    cpace_compute_confirmation(&s->cpace, role_expected, expected_mac);

    /* Constant-time comparison is mandatory: prevents an attacker from
     * guessing the MAC one byte at a time via a timing attack. */
    if (sodium_memcmp(expected_mac, peer_mac, CPACE_MACBYTES) != 0) {
        s->state = SESSION_BROKEN;
        sodium_memzero(expected_mac, sizeof(expected_mac));
        return -1; /* suspected room_code typo or active attacker */
    }
    sodium_memzero(expected_mac, sizeof(expected_mac));

    if (chat_crypto_start(&s->crypto, s->cpace.session_key, s->is_initiator, s->my_header) != 0) {
        s->state = SESSION_BROKEN;
        return -1;
    }

    s->state = SESSION_WAIT_HEADER;
    return 0;
}

int session_on_peer_header(chat_session *s, const uint8_t peer_header[CHAT_HEADERBYTES])
{
    if (s->state != SESSION_WAIT_HEADER) return -1;

    if (chat_crypto_finish_handshake(&s->crypto, peer_header) != 0) {
        s->state = SESSION_BROKEN;
        return -1;
    }

    s->state = SESSION_ACTIVE;
    return 0;
}

int session_encrypt(chat_session *s, const uint8_t *msg, size_t msg_len,
                     uint8_t *out_ct, size_t out_ct_cap, size_t *out_ct_len, int is_final)
{
    if (s->state != SESSION_ACTIVE) return -1;

    if (chat_crypto_encrypt_padded(&s->crypto, msg, msg_len, out_ct, out_ct_cap, out_ct_len, is_final) != 0)
        return -1;

    if (is_final) s->state = SESSION_CLOSED;
    return 0;
}

int session_decrypt(chat_session *s, const uint8_t *ct, size_t ct_len,
                     uint8_t *out_msg, size_t out_msg_cap, size_t *out_msg_len, int *out_is_final)
{
    if (s->state != SESSION_ACTIVE) return -1;

    if (chat_crypto_decrypt_padded(&s->crypto, ct, ct_len, out_msg, out_msg_cap, out_msg_len, out_is_final) != 0) {
        s->state = SESSION_BROKEN; /* chain broken; this session can no longer decrypt */
        return -1;
    }

    if (*out_is_final) s->state = SESSION_CLOSED;
    return 0;
}

int session_reconnect(chat_session *s)
{
    char room_code[ROOM_CODE_MAXLEN];
    char room_id[ROOM_ID_MAXLEN];
    size_t rc_len, ri_len;
    int is_initiator;

    if (s->state != SESSION_BROKEN) return -1;

    /* Save just the room_code/room_id, then wipe everything including key
     * material and rebuild from scratch. */
    rc_len = s->room_code_len;
    ri_len = s->room_id_len;
    memcpy(room_code, s->room_code, rc_len);
    memcpy(room_id, s->room_id, ri_len);
    is_initiator = s->is_initiator;

    session_wipe(s);

    return session_begin(s, room_code, rc_len, room_id, ri_len, is_initiator);
}

void session_wipe(chat_session *s)
{
    chat_crypto_wipe(&s->crypto);
    sodium_memzero(&s->cpace, sizeof(s->cpace));
    sodium_memzero(s, sizeof(*s));
}
