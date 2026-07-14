#ifndef WS_FRAME_H
#define WS_FRAME_H

#include <stdint.h>
#include <stddef.h>

/* RFC 6455 opcodes */
typedef enum {
    WS_OP_CONTINUATION = 0x0,
    WS_OP_TEXT         = 0x1,
    WS_OP_BINARY       = 0x2,
    WS_OP_CLOSE        = 0x8,
    WS_OP_PING         = 0x9,
    WS_OP_PONG         = 0xA
} ws_opcode_t;

typedef struct {
    int fin;
    ws_opcode_t opcode;
    int masked;
    uint64_t payload_len;
    uint8_t mask_key[4];
    size_t header_len; /* number of bytes this header occupied in the buffer (including the mask key) */
} ws_frame_header_t;

/*
 * Encodes a text frame per the RFC 6455 client spec (masking required).
 * Returns -1 if out_cap is insufficient. On success returns the total
 * number of bytes written.
 */
int ws_encode_text_frame(uint8_t *out, size_t out_cap,
                          const uint8_t *payload, size_t payload_len);

/* Encodes a close/ping/pong control frame (masking required for all of these) */
int ws_encode_control_frame(uint8_t *out, size_t out_cap,
                             ws_opcode_t opcode,
                             const uint8_t *payload, size_t payload_len);

/*
 * Parses the frame header at the start of the buffer (does not include the
 * payload body). Returns -2 (insufficient data, wait for more) if buf_len
 * is shorter than the full header. Returns -1 for a malformed frame.
 * Returns: 0 = success
 */
int ws_parse_frame_header(const uint8_t *buf, size_t buf_len, ws_frame_header_t *out);

/*
 * Unmasks a payload (server responses are normally unmasked, but this is
 * kept general-purpose in case masked=1 is ever encountered).
 * In-place transformation.
 */
void ws_unmask_payload(uint8_t *payload, size_t len, const uint8_t mask_key[4]);

#endif
