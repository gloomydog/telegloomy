#include "ws_frame.h"
#include <string.h>
#include <sodium.h>

void ws_unmask_payload(uint8_t *payload, size_t len, const uint8_t mask_key[4])
{
    for (size_t i = 0; i < len; i++)
        payload[i] ^= mask_key[i % 4];
}

static int encode_frame(uint8_t *out, size_t out_cap, int fin, ws_opcode_t opcode,
                         const uint8_t *payload, size_t payload_len)
{
    size_t pos = 0;
    uint8_t mask_key[4];

    /* Worst case (64-bit length + mask) header size is 2+8+4=14 bytes. */
    if (out_cap < 14 + payload_len) return -1;

    out[pos++] = (uint8_t)((fin ? 0x80 : 0x00) | (opcode & 0x0F));

    if (payload_len < 126) {
        out[pos++] = 0x80 | (uint8_t)payload_len; /* MASK bit always 1 (client -> server) */
    } else if (payload_len <= 0xFFFF) {
        out[pos++] = 0x80 | 126;
        out[pos++] = (uint8_t)((payload_len >> 8) & 0xFF);
        out[pos++] = (uint8_t)(payload_len & 0xFF);
    } else {
        out[pos++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--)
            out[pos++] = (uint8_t)((payload_len >> (8 * i)) & 0xFF);
    }

    /* RFC 6455 compliance: every frame from the client must be masked.
     * The mask key must be unpredictable (this is a spec requirement,
     * intended as a defense against proxy cache-poisoning attacks), so we
     * use a cryptographic CSPRNG. */
    randombytes_buf(mask_key, sizeof(mask_key));
    memcpy(out + pos, mask_key, 4);
    pos += 4;

    for (size_t i = 0; i < payload_len; i++)
        out[pos + i] = payload[i] ^ mask_key[i % 4];
    pos += payload_len;

    return (int)pos;
}

int ws_encode_text_frame(uint8_t *out, size_t out_cap,
                          const uint8_t *payload, size_t payload_len)
{
    return encode_frame(out, out_cap, 1, WS_OP_TEXT, payload, payload_len);
}

int ws_encode_control_frame(uint8_t *out, size_t out_cap,
                             ws_opcode_t opcode,
                             const uint8_t *payload, size_t payload_len)
{
    /* Per RFC 6455, control frames must have a payload of 125 bytes or
     * less and must not be fragmented. */
    if (payload_len > 125) return -1;
    return encode_frame(out, out_cap, 1, opcode, payload, payload_len);
}

int ws_parse_frame_header(const uint8_t *buf, size_t buf_len, ws_frame_header_t *out)
{
    size_t pos = 0;

    if (buf_len < 2) return -2;

    uint8_t b0 = buf[pos++];
    uint8_t b1 = buf[pos++];

    out->fin = (b0 >> 7) & 1;
    /* RSV1-3 bits (for extensions) are unused here so they're ignored. */
    out->opcode = (ws_opcode_t)(b0 & 0x0F);
    out->masked = (b1 >> 7) & 1;

    uint8_t len7 = b1 & 0x7F;

    if (len7 < 126) {
        out->payload_len = len7;
    } else if (len7 == 126) {
        if (buf_len < pos + 2) return -2;
        out->payload_len = ((uint64_t)buf[pos] << 8) | buf[pos + 1];
        pos += 2;
    } else {
        if (buf_len < pos + 8) return -2;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | buf[pos + i];
        out->payload_len = v;
        pos += 8;
    }

    if (out->masked) {
        if (buf_len < pos + 4) return -2;
        memcpy(out->mask_key, buf + pos, 4);
        pos += 4;
    } else {
        memset(out->mask_key, 0, 4);
    }

    out->header_len = pos;
    return 0;
}
