#ifndef ENVELOPE_H
#define ENVELOPE_H

#include <stdint.h>
#include <stddef.h>

/*
 * JSON format carried in a Nostr event's content:
 *   {"v":1,"room":"<room_id>","type":"point|confirm|header|msg","role":"A|B","data":"<base64>"}
 *
 * "role" is only meaningful for point/confirm (it is the sender's CPace
 * role, A or B). It can be omitted (empty string) for header/msg since
 * those occur within an already-established session.
 *
 * room_id duplicates the Nostr-side ["r", room_id] tag, but is included
 * redundantly in the content too as a defense in case a relay mangles or
 * drops tags.
 */

typedef enum {
    ENVELOPE_POINT,   /* CPace round 1: public point Y (32 bytes) */
    ENVELOPE_CONFIRM, /* CPace round 2: confirmation MAC (32 bytes) */
    ENVELOPE_HEADER,  /* secretstream header (24 bytes) */
    ENVELOPE_MSG,      /* the encrypted chat message body */
    ENVELOPE_UNKNOWN
} envelope_type_t;

#define ENVELOPE_ROOM_MAXLEN 64
#define ENVELOPE_DATA_MAXLEN 8192 /* generous margin to cover the largest expected msg ciphertext */

typedef struct {
    char room_id[ENVELOPE_ROOM_MAXLEN];
    envelope_type_t type;
    char role[2]; /* "A", "B", or empty string */
    uint8_t data[ENVELOPE_DATA_MAXLEN];
    size_t data_len;
} envelope_t;

/*
 * Serializes an envelope into a JSON string, written to out_buf.
 * On success returns the number of characters written (not counting the
 * terminating NUL). On failure returns -1 (e.g. insufficient buffer).
 */
int envelope_build(char *out_buf, size_t out_buf_cap,
                    const char *room_id, envelope_type_t type, const char *role,
                    const uint8_t *data, size_t data_len);

/*
 * Parses a JSON string. Since this handles untrusted network input, types
 * and lengths are checked strictly, and any anomaly always returns -1.
 * Returns: 0 = success, -1 = invalid JSON / missing field / size overflow
 */
int envelope_parse(const char *json_str, envelope_t *out);

#endif
