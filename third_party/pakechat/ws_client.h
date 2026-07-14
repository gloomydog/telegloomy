#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include <stddef.h>
#include <pthread.h>
#include <openssl/ssl.h>

typedef struct {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int sockfd;
    char client_key[32]; /* kept around for handshake verification */
    int connected;
    int closed; /* CLOSE frame sent/received */

    /* A single SSL object must never be touched by SSL_read and SSL_write
     * concurrently (OpenSSL objects are not safe for simultaneous use).
     * All access to ctx->ssl is serialized through this lock. To keep a
     * blocking read from starving writers, the socket is non-blocking and
     * the receive path polls (releasing the lock between polls) rather
     * than blocking inside SSL_read while holding the lock. */
    pthread_mutex_t io_lock;

    /* Receive buffer: since TCP/TLS data can arrive split at arbitrary
     * boundaries, we buffer it here in case a frame spans multiple reads. */
    uint8_t recv_buf[65536];
    size_t recv_buf_len;
} ws_client_t;

/*
 * Opens a TLS connection to wss://host:port/path and completes the
 * WebSocket handshake. Server certificate verification uses the default
 * system CA store (the connection is aborted on verification failure).
 * Returns: 0 = success (ready to send/receive), -1 = failure
 */
int ws_client_connect(ws_client_t *ctx, const char *host, int port, const char *path);

/* Sends one text message (automatically frames and masks it internally). */
int ws_client_send_text(ws_client_t *ctx, const uint8_t *payload, size_t payload_len);

/*
 * Blocks until one complete text message has been received
 * (continuation frames are reassembled internally; a received ping is
 * automatically answered with a pong; a received close frame sets
 * ctx->closed=1 and returns -1).
 * Returns: number of bytes received, 0 = connection closed, -1 = error
 */
int ws_client_recv_text(ws_client_t *ctx, uint8_t *out_buf, size_t out_cap);

/* Sends a close handshake and terminates the connection. */
void ws_client_close(ws_client_t *ctx);

/* Interrupt a blocking recv on another thread (does NOT free SSL/socket).
 * Call this, join the reader thread, then ws_client_close(). */
void ws_client_shutdown(ws_client_t *ctx);

#endif
