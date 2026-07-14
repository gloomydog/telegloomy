#ifndef WS_HANDSHAKE_H
#define WS_HANDSHAKE_H

#include <stddef.h>

/* Generates a random 16 bytes for Sec-WebSocket-Key and base64-encodes it.
 * out_cap needs at least 25 bytes (24 chars + NUL). */
int ws_generate_client_key(char *out, size_t out_cap);

/*
 * Computes the Accept-Key from client_key and the RFC 6455 fixed GUID via
 * SHA1 -> base64. out_cap needs at least 29 bytes (28 chars + NUL).
 */
int ws_compute_accept_key(const char *client_key_b64, char *out, size_t out_cap);

/*
 * Verifies that the Sec-WebSocket-Accept header value returned by the
 * server is correct for the client_key we sent. Skipping this would miss
 * a spoofed handshake.
 * Returns: 1 = match, 0 = mismatch / computation failure
 */
int ws_verify_accept(const char *client_key_b64, const char *server_accept_b64);

/*
 * Builds an HTTP Upgrade request. Returns -1 if out_cap is insufficient.
 * path is a query-less path like "/"; host may include a port number
 * ("relay.example.com" etc. also works).
 * On success returns the number of characters written.
 */
int ws_build_upgrade_request(char *out, size_t out_cap,
                              const char *host, const char *path,
                              const char *client_key_b64);

#endif
