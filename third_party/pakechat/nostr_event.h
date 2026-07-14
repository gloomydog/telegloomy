#ifndef NOSTR_EVENT_H
#define NOSTR_EVENT_H

#include <stddef.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>

typedef struct {
    unsigned char privkey[32];
    secp256k1_keypair keypair;
    char pubkey_hex[65]; /* x-only pubkey, 32 bytes -> 64 hex chars + NUL */
} nostr_identity_t;

/* Generates a single disposable identity (an ephemeral keypair) for this
 * chat session. Meant to be regenerated fresh per room / per run, to
 * minimize traceability.
 * Returns: 0 = success, -1 = failure (random generation or secp256k1
 * context initialization failed) */
int nostr_identity_generate(nostr_identity_t *id);

/*
 * Builds and signs a single NIP-01-compliant EVENT JSON (given a kind, a
 * single ["r",room_tag] tag, and content). out_json receives the finished
 * single-event JSON object.
 * Returns: number of characters written, -1 = failure
 */
int nostr_build_event(const nostr_identity_t *id, int kind,
                       const char *room_tag, const char *content,
                       char *out_json, size_t out_cap);

/* Builds the ["EVENT", {event}] message sent to a relay. */
int nostr_wrap_event_msg(const char *event_json, char *out_json, size_t out_cap);

/* Builds a ["REQ", sub_id, {"kinds":[kind],"#r":[room_tag]}] subscription request. */
int nostr_build_req(const char *sub_id, int kind, const char *room_tag,
                     char *out_json, size_t out_cap);

/* Builds a ["CLOSE", sub_id] unsubscribe message. */
int nostr_build_close(const char *sub_id, char *out_json, size_t out_cap);

/*
 * Parses an incoming ["EVENT", sub_id, {event}] from a relay and extracts
 * the content string and the sender's pubkey_hex. Also performs signature
 * verification, rejecting invalid signatures.
 * Returns -1 if out_content_cap is insufficient. For other message types
 * such as ["EOSE",...] or ["NOTICE",...], returns -2 (the caller may
 * safely ignore these).
 * Returns: 0 = success, -1 = failure/invalid, -2 = a non-EVENT message
 */
int nostr_parse_incoming(const char *json_str,
                          char *out_pubkey_hex, size_t out_pubkey_cap,
                          char *out_content, size_t out_content_cap);

/* Releases the cached secp256k1 context. Optional -- the OS reclaims it at
 * process exit anyway -- but call it for a clean shutdown. */
void nostr_cleanup(void);

#endif
