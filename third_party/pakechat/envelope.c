#include "envelope.h"
#include <cjson/cJSON.h>
#include <sodium.h>
#include <string.h>
#include <stdio.h>

#define ENVELOPE_VERSION 1
#define B64_VARIANT sodium_base64_VARIANT_ORIGINAL

static const char *type_to_str(envelope_type_t t) {
    switch (t) {
        case ENVELOPE_POINT:   return "point";
        case ENVELOPE_CONFIRM: return "confirm";
        case ENVELOPE_HEADER:  return "header";
        case ENVELOPE_MSG:     return "msg";
        default: return NULL;
    }
}

static envelope_type_t str_to_type(const char *s) {
    if (!s) return ENVELOPE_UNKNOWN;
    if (strcmp(s, "point") == 0)   return ENVELOPE_POINT;
    if (strcmp(s, "confirm") == 0) return ENVELOPE_CONFIRM;
    if (strcmp(s, "header") == 0)  return ENVELOPE_HEADER;
    if (strcmp(s, "msg") == 0)     return ENVELOPE_MSG;
    return ENVELOPE_UNKNOWN;
}

int envelope_build(char *out_buf, size_t out_buf_cap,
                    const char *room_id, envelope_type_t type, const char *role,
                    const uint8_t *data, size_t data_len)
{
    const char *type_str = type_to_str(type);
    if (!type_str) return -1;
    if (data_len > ENVELOPE_DATA_MAXLEN) return -1;

    size_t b64_cap = sodium_base64_ENCODED_LEN(data_len, B64_VARIANT);
    char *b64 = malloc(b64_cap);
    if (!b64) return -1;
    sodium_bin2base64(b64, b64_cap, data, data_len, B64_VARIANT);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "v", ENVELOPE_VERSION);
    cJSON_AddStringToObject(root, "room", room_id ? room_id : "");
    cJSON_AddStringToObject(root, "type", type_str);
    cJSON_AddStringToObject(root, "role", (role && *role) ? role : "");
    cJSON_AddStringToObject(root, "data", b64);
    free(b64);

    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!printed) return -1;

    size_t plen = strlen(printed);
    if (plen + 1 > out_buf_cap) { free(printed); return -1; }
    memcpy(out_buf, printed, plen + 1);
    free(printed);
    return (int)plen;
}

int envelope_parse(const char *json_str, envelope_t *out)
{
    memset(out, 0, sizeof(*out));

    cJSON *root = cJSON_Parse(json_str);
    if (!root) return -1;

    cJSON *v = cJSON_GetObjectItemCaseSensitive(root, "v");
    cJSON *room = cJSON_GetObjectItemCaseSensitive(root, "room");
    cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "type");
    cJSON *role = cJSON_GetObjectItemCaseSensitive(root, "role");
    cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");

    /* Presence/type checks on required fields. This is untrusted input,
     * so we don't relax anything here. */
    if (!cJSON_IsNumber(v) || v->valueint != ENVELOPE_VERSION) { cJSON_Delete(root); return -1; }
    if (!cJSON_IsString(room) || !cJSON_IsString(type) ||
        !cJSON_IsString(role) || !cJSON_IsString(data)) { cJSON_Delete(root); return -1; }

    if (strlen(room->valuestring) >= ENVELOPE_ROOM_MAXLEN) { cJSON_Delete(root); return -1; }
    strcpy(out->room_id, room->valuestring);

    out->type = str_to_type(type->valuestring);
    if (out->type == ENVELOPE_UNKNOWN) { cJSON_Delete(root); return -1; }

    if (strlen(role->valuestring) >= sizeof(out->role)) { cJSON_Delete(root); return -1; }
    strcpy(out->role, role->valuestring);

    size_t decoded_max = strlen(data->valuestring); /* decoded length is always shorter than the base64 length */
    if (decoded_max > sizeof(out->data)) { cJSON_Delete(root); return -1; }

    size_t decoded_len = 0;
    int rc = sodium_base642bin(out->data, sizeof(out->data),
                                data->valuestring, strlen(data->valuestring),
                                NULL, &decoded_len, NULL, B64_VARIANT);
    cJSON_Delete(root);

    if (rc != 0) return -1; /* invalid base64 */
    out->data_len = decoded_len;
    return 0;
}
