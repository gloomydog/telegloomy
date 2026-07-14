#include "ws_handshake.h"
#include <string.h>
#include <stdio.h>
#include <sodium.h>
#include <openssl/sha.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define B64_VARIANT sodium_base64_VARIANT_ORIGINAL

int ws_generate_client_key(char *out, size_t out_cap)
{
    uint8_t raw[16];
    size_t need = sodium_base64_ENCODED_LEN(sizeof(raw), B64_VARIANT);
    if (out_cap < need) return -1;

    randombytes_buf(raw, sizeof(raw));
    sodium_bin2base64(out, out_cap, raw, sizeof(raw), B64_VARIANT);
    return 0;
}

int ws_compute_accept_key(const char *client_key_b64, char *out, size_t out_cap)
{
    char concat[256];
    unsigned char digest[SHA_DIGEST_LENGTH]; /* SHA1: 20 bytes */
    size_t need;

    int n = snprintf(concat, sizeof(concat), "%s%s", client_key_b64, WS_GUID);
    if (n < 0 || (size_t)n >= sizeof(concat)) return -1;

    /* We use SHA1 here because the WS handshake spec (RFC 6455) mandates
     * it. This isn't a confidentiality-critical use of crypto -- it's just
     * a protocol-level echo-back check (confirming a proxy understood the
     * handshake) -- so SHA1's weak collision resistance has no bearing on
     * the security of this use case. */
    SHA1((const unsigned char *)concat, (size_t)n, digest);

    need = sodium_base64_ENCODED_LEN(sizeof(digest), B64_VARIANT);
    if (out_cap < need) return -1;
    sodium_bin2base64(out, out_cap, digest, sizeof(digest), B64_VARIANT);
    return 0;
}

int ws_verify_accept(const char *client_key_b64, const char *server_accept_b64)
{
    char expected[64];
    if (ws_compute_accept_key(client_key_b64, expected, sizeof(expected)) != 0)
        return 0;
    /* The Accept-Key isn't secret, so a plain strcmp is fine here
     * (there's no information a timing attack could extract). */
    return strcmp(expected, server_accept_b64) == 0;
}

int ws_build_upgrade_request(char *out, size_t out_cap,
                              const char *host, const char *path,
                              const char *client_key_b64)
{
    int n = snprintf(out, out_cap,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: pakechat/0.1\r\n"
        "Origin: https://%s\r\n"
        "\r\n",
        path, host, client_key_b64, host);

    if (n < 0 || (size_t)n >= out_cap) return -1;
    return n;
}
