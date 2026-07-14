#include "nostr_event.h"
#include <cjson/cJSON.h>
#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static secp256k1_context *g_ctx = NULL;

static secp256k1_context *get_ctx(void)
{
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (g_ctx) {
            unsigned char seed[32];
            randombytes_buf(seed, sizeof(seed));
            /* Side-channel countermeasure via randomization. Recommended
             * to use a fresh random value on every call. */
            if (!secp256k1_context_randomize(g_ctx, seed)) {
                secp256k1_context_destroy(g_ctx);
                g_ctx = NULL;
            }
            sodium_memzero(seed, sizeof(seed));
        }
    }
    return g_ctx;
}

void nostr_cleanup(void)
{
    if (g_ctx) {
        secp256k1_context_destroy(g_ctx);
        g_ctx = NULL;
    }
}

int nostr_identity_generate(nostr_identity_t *id)
{
    secp256k1_context *ctx = get_ctx();
    if (!ctx) return -1;

    /* Keep regenerating with the CSPRNG until we get a valid secret key
     * (this succeeds almost immediately in practice). */
    do {
        randombytes_buf(id->privkey, sizeof(id->privkey));
    } while (!secp256k1_ec_seckey_verify(ctx, id->privkey));

    if (!secp256k1_keypair_create(ctx, &id->keypair, id->privkey)) return -1;

    secp256k1_xonly_pubkey xonly;
    if (!secp256k1_keypair_xonly_pub(ctx, &xonly, NULL, &id->keypair)) return -1;

    unsigned char pub32[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, pub32, &xonly)) return -1;

    sodium_bin2hex(id->pubkey_hex, sizeof(id->pubkey_hex), pub32, sizeof(pub32));
    return 0;
}

/* Builds the canonical array [0,pubkey,created_at,kind,tags,content] used
 * for the NIP-01 id computation, as a compact JSON string (the caller
 * must free() the result). */
static char *build_canonical(const char *pubkey_hex, long created_at, int kind,
                              const char *room_tag, const char *content)
{
    cJSON *arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(0));
    cJSON_AddItemToArray(arr, cJSON_CreateString(pubkey_hex));
    cJSON_AddItemToArray(arr, cJSON_CreateNumber((double)created_at));
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(kind));

    cJSON *tags = cJSON_CreateArray();
    if (room_tag) {
        cJSON *tag = cJSON_CreateArray();
        cJSON_AddItemToArray(tag, cJSON_CreateString("r"));
        cJSON_AddItemToArray(tag, cJSON_CreateString(room_tag));
        cJSON_AddItemToArray(tags, tag);
    }
    cJSON_AddItemToArray(arr, tags);
    cJSON_AddItemToArray(arr, cJSON_CreateString(content));

    char *s = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return s;
}

int nostr_build_event(const nostr_identity_t *id, int kind,
                       const char *room_tag, const char *content,
                       char *out_json, size_t out_cap)
{
    secp256k1_context *ctx = get_ctx();
    if (!ctx) return -1;

    long created_at = (long)time(NULL);

    char *canonical = build_canonical(id->pubkey_hex, created_at, kind, room_tag, content);
    if (!canonical) return -1;

    unsigned char id_hash[crypto_hash_sha256_BYTES]; /* 32 bytes */
    crypto_hash_sha256((unsigned char *)id_hash, (const unsigned char *)canonical, strlen(canonical));
    free(canonical);

    unsigned char aux_rand[32];
    randombytes_buf(aux_rand, sizeof(aux_rand));
    unsigned char sig[64];
    int ok = secp256k1_schnorrsig_sign32(ctx, sig, id_hash, &id->keypair, aux_rand);
    sodium_memzero(aux_rand, sizeof(aux_rand));
    if (!ok) return -1;

    char id_hex[65], sig_hex[129];
    sodium_bin2hex(id_hex, sizeof(id_hex), id_hash, sizeof(id_hash));
    sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, sizeof(sig));

    cJSON *ev = cJSON_CreateObject();
    cJSON_AddStringToObject(ev, "id", id_hex);
    cJSON_AddStringToObject(ev, "pubkey", id->pubkey_hex);
    cJSON_AddNumberToObject(ev, "created_at", (double)created_at);
    cJSON_AddNumberToObject(ev, "kind", kind);

    cJSON *tags = cJSON_CreateArray();
    if (room_tag) {
        cJSON *tag = cJSON_CreateArray();
        cJSON_AddItemToArray(tag, cJSON_CreateString("r"));
        cJSON_AddItemToArray(tag, cJSON_CreateString(room_tag));
        cJSON_AddItemToArray(tags, tag);
    }
    cJSON_AddItemToObject(ev, "tags", tags);
    cJSON_AddStringToObject(ev, "content", content);
    cJSON_AddStringToObject(ev, "sig", sig_hex);

    char *printed = cJSON_PrintUnformatted(ev);
    cJSON_Delete(ev);
    if (!printed) return -1;

    size_t plen = strlen(printed);
    if (plen + 1 > out_cap) { free(printed); return -1; }
    memcpy(out_json, printed, plen + 1);
    free(printed);
    return (int)plen;
}

int nostr_wrap_event_msg(const char *event_json, char *out_json, size_t out_cap)
{
    cJSON *ev = cJSON_Parse(event_json);
    if (!ev) return -1;

    cJSON *arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, cJSON_CreateString("EVENT"));
    cJSON_AddItemToArray(arr, ev); /* arr now owns this */

    char *printed = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    if (!printed) return -1;

    size_t plen = strlen(printed);
    if (plen + 1 > out_cap) { free(printed); return -1; }
    memcpy(out_json, printed, plen + 1);
    free(printed);
    return (int)plen;
}

int nostr_build_req(const char *sub_id, int kind, const char *room_tag,
                     char *out_json, size_t out_cap)
{
    cJSON *arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, cJSON_CreateString("REQ"));
    cJSON_AddItemToArray(arr, cJSON_CreateString(sub_id));

    cJSON *filter = cJSON_CreateObject();
    cJSON *kinds = cJSON_CreateArray();
    cJSON_AddItemToArray(kinds, cJSON_CreateNumber(kind));
    cJSON_AddItemToObject(filter, "kinds", kinds);

    cJSON *rtag = cJSON_CreateArray();
    cJSON_AddItemToArray(rtag, cJSON_CreateString(room_tag));
    cJSON_AddItemToObject(filter, "#r", rtag);

    cJSON_AddItemToArray(arr, filter);

    char *printed = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    if (!printed) return -1;

    size_t plen = strlen(printed);
    if (plen + 1 > out_cap) { free(printed); return -1; }
    memcpy(out_json, printed, plen + 1);
    free(printed);
    return (int)plen;
}

int nostr_build_close(const char *sub_id, char *out_json, size_t out_cap)
{
    cJSON *arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, cJSON_CreateString("CLOSE"));
    cJSON_AddItemToArray(arr, cJSON_CreateString(sub_id));

    char *printed = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    if (!printed) return -1;

    size_t plen = strlen(printed);
    if (plen + 1 > out_cap) { free(printed); return -1; }
    memcpy(out_json, printed, plen + 1);
    free(printed);
    return (int)plen;
}

int nostr_parse_incoming(const char *json_str,
                          char *out_pubkey_hex, size_t out_pubkey_cap,
                          char *out_content, size_t out_content_cap)
{
    secp256k1_context *ctx = get_ctx();
    if (!ctx) return -1;

    cJSON *arr = cJSON_Parse(json_str);
    if (!arr || !cJSON_IsArray(arr)) { cJSON_Delete(arr); return -1; }

    cJSON *type = cJSON_GetArrayItem(arr, 0);
    if (!cJSON_IsString(type)) { cJSON_Delete(arr); return -1; }
    if (strcmp(type->valuestring, "EVENT") != 0) { cJSON_Delete(arr); return -2; }

    cJSON *ev = cJSON_GetArrayItem(arr, 2); /* ["EVENT", sub_id, {event}] */
    if (!cJSON_IsObject(ev)) { cJSON_Delete(arr); return -1; }

    cJSON *pubkey = cJSON_GetObjectItemCaseSensitive(ev, "pubkey");
    cJSON *created_at = cJSON_GetObjectItemCaseSensitive(ev, "created_at");
    cJSON *kind = cJSON_GetObjectItemCaseSensitive(ev, "kind");
    cJSON *content = cJSON_GetObjectItemCaseSensitive(ev, "content");
    cJSON *id_field = cJSON_GetObjectItemCaseSensitive(ev, "id");
    cJSON *sig_field = cJSON_GetObjectItemCaseSensitive(ev, "sig");
    cJSON *tags = cJSON_GetObjectItemCaseSensitive(ev, "tags");

    if (!cJSON_IsString(pubkey) || !cJSON_IsNumber(created_at) || !cJSON_IsNumber(kind) ||
        !cJSON_IsString(content) || !cJSON_IsString(id_field) || !cJSON_IsString(sig_field) ||
        !cJSON_IsArray(tags)) {
        cJSON_Delete(arr); return -1;
    }

    /* Pull room_tag out of tags (look for ["r", room_tag]). */
    const char *room_tag = NULL;
    int tag_count = cJSON_GetArraySize(tags);
    for (int i = 0; i < tag_count; i++) {
        cJSON *tag = cJSON_GetArrayItem(tags, i);
        if (cJSON_IsArray(tag) && cJSON_GetArraySize(tag) >= 2) {
            cJSON *k = cJSON_GetArrayItem(tag, 0);
            cJSON *v = cJSON_GetArrayItem(tag, 1);
            if (cJSON_IsString(k) && cJSON_IsString(v) && strcmp(k->valuestring, "r") == 0) {
                room_tag = v->valuestring;
                break;
            }
        }
    }

    /* --- consistency check by recomputing id --- */
    char *canonical = build_canonical(pubkey->valuestring, (long)created_at->valuedouble,
                                       kind->valueint, room_tag, content->valuestring);
    if (!canonical) { cJSON_Delete(arr); return -1; }

    unsigned char computed_id[32];
    crypto_hash_sha256(computed_id, (const unsigned char *)canonical, strlen(canonical));
    free(canonical);

    unsigned char claimed_id[32];
    if (strlen(id_field->valuestring) != 64 ||
        sodium_hex2bin(claimed_id, sizeof(claimed_id), id_field->valuestring, 64, NULL, NULL, NULL) != 0) {
        cJSON_Delete(arr); return -1;
    }
    if (sodium_memcmp(computed_id, claimed_id, 32) != 0) { cJSON_Delete(arr); return -1; } /* id was tampered with */

    /* --- signature verification --- */
    unsigned char pubkey_bin[32];
    if (strlen(pubkey->valuestring) != 64 ||
        sodium_hex2bin(pubkey_bin, sizeof(pubkey_bin), pubkey->valuestring, 64, NULL, NULL, NULL) != 0) {
        cJSON_Delete(arr); return -1;
    }
    secp256k1_xonly_pubkey xonly;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xonly, pubkey_bin)) { cJSON_Delete(arr); return -1; }

    unsigned char sig_bin[64];
    if (strlen(sig_field->valuestring) != 128 ||
        sodium_hex2bin(sig_bin, sizeof(sig_bin), sig_field->valuestring, 128, NULL, NULL, NULL) != 0) {
        cJSON_Delete(arr); return -1;
    }

    if (!secp256k1_schnorrsig_verify(ctx, sig_bin, computed_id, 32, &xonly)) {
        cJSON_Delete(arr); return -1; /* signature mismatch = impersonation or tampering */
    }

    if (strlen(pubkey->valuestring) + 1 > out_pubkey_cap) { cJSON_Delete(arr); return -1; }
    strcpy(out_pubkey_hex, pubkey->valuestring);

    if (strlen(content->valuestring) + 1 > out_content_cap) { cJSON_Delete(arr); return -1; }
    strcpy(out_content, content->valuestring);

    cJSON_Delete(arr);
    return 0;
}
