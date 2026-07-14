#define _GNU_SOURCE
#include "ws_client.h"
#include "ws_handshake.h"
#include "ws_frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>

static int tcp_connect(const char *host, int port)
{
    char port_str[16];
    struct addrinfo hints, *res, *rp;
    int sockfd = -1;

    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        fprintf(stderr, "[ws] DNS resolution failed: %s\n", host);
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) continue;
        int fl = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, fl | O_NONBLOCK);           /* non-blocking connect */
        int rc = connect(sockfd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) { fcntl(sockfd, F_SETFL, fl); break; }
        if (rc < 0 && errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = sockfd, .events = POLLOUT };
            int pr = poll(&pfd, 1, 5000);                  /* 5s connect timeout */
            if (pr > 0) {
                int err = 0; socklen_t el = sizeof err;
                getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &el);
                if (err == 0) { fcntl(sockfd, F_SETFL, fl); break; }
            } else if (pr == 0) {
                fprintf(stderr, "[ws] connect timed out: %s:%d\n", host, port);
            }
        } else {
            perror("[ws] connect");
        }
        close(sockfd);
        sockfd = -1;
    }
    freeaddrinfo(res);
    return sockfd;
}

/* Compacts recv_buf by discarding the consumed bytes at the front. */
static void recv_buf_consume(ws_client_t *ctx, size_t n)
{
    if (n >= ctx->recv_buf_len) {
        ctx->recv_buf_len = 0;
        return;
    }
    memmove(ctx->recv_buf, ctx->recv_buf + n, ctx->recv_buf_len - n);
    ctx->recv_buf_len -= n;
}

/* Reads more data from SSL into recv_buf. The caller holds io_lock; on a
 * would-block condition this releases io_lock while polling so that writers
 * on the other thread aren't starved, then reacquires it before returning.
 * Returns 0 on success (bytes appended), -1 on error/EOF. */
static int recv_buf_fill_more(ws_client_t *ctx)
{
    if (ctx->recv_buf_len >= sizeof(ctx->recv_buf)) return -1; /* buffer exhausted */

    for (;;) {
        int n = SSL_read(ctx->ssl, ctx->recv_buf + ctx->recv_buf_len,
                          (int)(sizeof(ctx->recv_buf) - ctx->recv_buf_len));
        if (n > 0) { ctx->recv_buf_len += (size_t)n; return 0; }

        int err = SSL_get_error(ctx->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd = { .fd = ctx->sockfd,
                                  .events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN };
            /* Release the lock so a concurrent writer can make progress
             * while we wait for the socket. */
            pthread_mutex_unlock(&ctx->io_lock);
            int pr = poll(&pfd, 1, 1000);
            pthread_mutex_lock(&ctx->io_lock);
            if (pr < 0 && errno != EINTR) return -1;
            continue; /* retry SSL_read (pr==0 timeout just loops again) */
        }
        return -1; /* SSL_ERROR_ZERO_RETURN (clean close) or a fatal error */
    }
}

int ws_client_connect(ws_client_t *ctx, const char *host, int port, const char *path)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->sockfd = tcp_connect(host, port);
    if (ctx->sockfd < 0) { fprintf(stderr, "[ws] TCP connection failed: %s:%d\n", host, port); return -1; }

    /* Bound the TLS + WebSocket handshake so an unresponsive relay can't hang
     * startup (socket is blocking here; it goes non-blocking after handshake). */
    { struct timeval _tv = { .tv_sec = 8, .tv_usec = 0 };
      setsockopt(ctx->sockfd, SOL_SOCKET, SO_RCVTIMEO, &_tv, sizeof _tv);
      setsockopt(ctx->sockfd, SOL_SOCKET, SO_SNDTIMEO, &_tv, sizeof _tv); }

    ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->ssl_ctx) { fprintf(stderr, "[ws] SSL_CTX_new failed\n"); close(ctx->sockfd); return -1; }

    /* Verify against the system's default CA store. Skipping this would
     * make it impossible to detect a MITM (relay impersonation), so it's
     * mandatory. */
    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_default_verify_paths(ctx->ssl_ctx) != 1) {
        fprintf(stderr, "[ws] Failed to load CA store (ca-certificates may not be installed)\n");
        SSL_CTX_free(ctx->ssl_ctx); close(ctx->sockfd); return -1;
    }

    ctx->ssl = SSL_new(ctx->ssl_ctx);
    if (!ctx->ssl) { fprintf(stderr, "[ws] SSL_new failed\n"); SSL_CTX_free(ctx->ssl_ctx); close(ctx->sockfd); return -1; }

    /* SNI: some relays serve a different certificate based on SNI, so this is required. */
    SSL_set_tlsext_host_name(ctx->ssl, host);

    /* Hostname verification (does the cert's CN/SAN match host?). Without
     * this, "the cert is valid but for anyone at all" -- i.e. verification
     * is effectively meaningless. */
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ctx->ssl);
    X509_VERIFY_PARAM_set_hostflags(vpm, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    X509_VERIFY_PARAM_set1_host(vpm, host, 0);

    SSL_set_fd(ctx->ssl, ctx->sockfd);

    if (SSL_connect(ctx->ssl) != 1) {
        fprintf(stderr, "[ws] TLS handshake failed: ");
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl); SSL_CTX_free(ctx->ssl_ctx); close(ctx->sockfd); return -1;
    }

    if (SSL_get_verify_result(ctx->ssl) != X509_V_OK) {
        fprintf(stderr, "[ws] Server certificate verification failed: %s\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ctx->ssl)));
        SSL_shutdown(ctx->ssl); SSL_free(ctx->ssl); SSL_CTX_free(ctx->ssl_ctx);
        close(ctx->sockfd); return -1;
    }

    /* --- WebSocket handshake --- */
    if (ws_generate_client_key(ctx->client_key, sizeof(ctx->client_key)) != 0) {
        fprintf(stderr, "[ws] Failed to generate client key\n"); goto fail;
    }

    char req[1024];
    int req_len = ws_build_upgrade_request(req, sizeof(req), host, path, ctx->client_key);
    if (req_len < 0) { fprintf(stderr, "[ws] Failed to build upgrade request\n"); goto fail; }
    if (SSL_write(ctx->ssl, req, req_len) != req_len) {
        fprintf(stderr, "[ws] Failed to send upgrade request: "); ERR_print_errors_fp(stderr); goto fail;
    }

    /* Keep reading until we see the end of the headers (\r\n\r\n). */
    char resp[4096];
    size_t resp_len = 0;
    for (;;) {
        int n = SSL_read(ctx->ssl, resp + resp_len, (int)(sizeof(resp) - resp_len - 1));
        if (n <= 0) {
            fprintf(stderr, "[ws] Failed to read handshake response: "); ERR_print_errors_fp(stderr);
            goto fail;
        }
        resp_len += (size_t)n;
        resp[resp_len] = '\0';
        if (strstr(resp, "\r\n\r\n") != NULL) break;
        if (resp_len >= sizeof(resp) - 1) { fprintf(stderr, "[ws] Handshake response abnormally large\n"); goto fail; }
    }

    if (strncmp(resp, "HTTP/1.1 101", 12) != 0) {
        fprintf(stderr, "[ws] Upgrade rejected. Server response:\n%s\n", resp);
        goto fail;
    }

    char *accept_hdr = strcasestr(resp, "Sec-WebSocket-Accept:");
    if (!accept_hdr) { fprintf(stderr, "[ws] Sec-WebSocket-Accept header not found\n"); goto fail; }
    accept_hdr += strlen("Sec-WebSocket-Accept:");
    while (*accept_hdr == ' ') accept_hdr++;
    char accept_val[64];
    size_t i = 0;
    while (*accept_hdr && *accept_hdr != '\r' && i < sizeof(accept_val) - 1)
        accept_val[i++] = *accept_hdr++;
    accept_val[i] = '\0';

    if (!ws_verify_accept(ctx->client_key, accept_val)) {
        fprintf(stderr, "[ws] Accept-Key mismatch (suspected spoofing, or an implementation bug)\n");
        goto fail;
    }

    /* Some WS frames may have already arrived right after the HTTP
     * headers, so hold onto that leftover data. */
    char *body_start = strstr(resp, "\r\n\r\n") + 4;
    size_t body_len = resp_len - (size_t)(body_start - resp);
    if (body_len > 0) {
        memcpy(ctx->recv_buf, body_start, body_len);
        ctx->recv_buf_len = body_len;
    }

    /* Handshake done (all reads/writes above were blocking). From here on
     * the send and receive paths run on different threads, so switch the
     * socket to non-blocking and initialize the I/O lock that serializes
     * access to the SSL object. */
    {
        int flags = fcntl(ctx->sockfd, F_GETFL, 0);
        if (flags == -1 || fcntl(ctx->sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
            fprintf(stderr, "[ws] Failed to set the socket non-blocking\n");
            goto fail;
        }
    }
    pthread_mutex_init(&ctx->io_lock, NULL);

    ctx->connected = 1;
    return 0;

fail:
    SSL_shutdown(ctx->ssl); SSL_free(ctx->ssl); SSL_CTX_free(ctx->ssl_ctx);
    close(ctx->sockfd);
    return -1;
}

/* Writes an entire buffer via SSL on a non-blocking socket, waiting on the
 * socket as needed for WANT_READ/WANT_WRITE. The caller must hold io_lock.
 * Returns 0 on success, -1 on failure. */
static int ssl_write_all_locked(ws_client_t *ctx, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ctx->ssl, buf + off, (int)(len - off));
        if (n > 0) { off += (size_t)n; continue; }

        int err = SSL_get_error(ctx->ssl, n);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            struct pollfd pfd = { .fd = ctx->sockfd,
                                  .events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN };
            int pr = poll(&pfd, 1, 5000);
            if (pr <= 0) return -1; /* timeout or error */
            continue;
        }
        return -1; /* fatal SSL error / connection closed */
    }
    return 0;
}

int ws_client_send_text(ws_client_t *ctx, const uint8_t *payload, size_t payload_len)
{
    uint8_t frame[65550];
    if (payload_len + 14 > sizeof(frame)) return -1; /* messages this large aren't supported by this implementation */

    int frame_len = ws_encode_text_frame(frame, sizeof(frame), payload, payload_len);
    if (frame_len < 0) return -1;

    pthread_mutex_lock(&ctx->io_lock);
    int rc = ssl_write_all_locked(ctx, frame, (size_t)frame_len);
    pthread_mutex_unlock(&ctx->io_lock);
    return rc;
}

/* Must be called with io_lock held (the receive loop already holds it when
 * it needs to answer a ping/close). */
static int send_control_locked(ws_client_t *ctx, ws_opcode_t opcode, const uint8_t *payload, size_t len)
{
    uint8_t frame[256];
    int frame_len = ws_encode_control_frame(frame, sizeof(frame), opcode, payload, len);
    if (frame_len < 0) return -1;
    return ssl_write_all_locked(ctx, frame, (size_t)frame_len);
}

int ws_client_recv_text(ws_client_t *ctx, uint8_t *out_buf, size_t out_cap)
{
    size_t assembled_len = 0;
    int result;

    pthread_mutex_lock(&ctx->io_lock);

    for (;;) {
        ws_frame_header_t hdr;
        int rc = ws_parse_frame_header(ctx->recv_buf, ctx->recv_buf_len, &hdr);
        if (rc == -2) {
            if (recv_buf_fill_more(ctx) != 0) { result = -1; goto out; }
            continue;
        }
        if (rc != 0) { result = -1; goto out; } /* malformed frame */

        /* Reject frames whose declared payload can't possibly fit in our
         * receive buffer. Without this, a malicious relay could announce a
         * huge payload_len and make us spin reading until the buffer fills.
         * Our own messages are at most a few hundred bytes, so any frame
         * approaching the buffer size is illegitimate. */
        if ((size_t)hdr.payload_len > sizeof(ctx->recv_buf) - hdr.header_len) {
            result = -1; goto out;
        }

        size_t total = hdr.header_len + (size_t)hdr.payload_len;
        if (ctx->recv_buf_len < total) {
            if (recv_buf_fill_more(ctx) != 0) { result = -1; goto out; }
            continue;
        }

        uint8_t *payload = ctx->recv_buf + hdr.header_len;
        if (hdr.masked) ws_unmask_payload(payload, (size_t)hdr.payload_len, hdr.mask_key);

        switch (hdr.opcode) {
        case WS_OP_PING:
            send_control_locked(ctx, WS_OP_PONG, payload, (size_t)hdr.payload_len);
            recv_buf_consume(ctx, total);
            continue;
        case WS_OP_PONG:
            recv_buf_consume(ctx, total);
            continue;
        case WS_OP_CLOSE:
            send_control_locked(ctx, WS_OP_CLOSE, payload, (size_t)hdr.payload_len > 125 ? 0 : (size_t)hdr.payload_len);
            ctx->closed = 1;
            recv_buf_consume(ctx, total);
            result = 0; goto out;
        case WS_OP_TEXT:
        case WS_OP_CONTINUATION:
            if (assembled_len + hdr.payload_len > out_cap) { recv_buf_consume(ctx, total); result = -1; goto out; }
            memcpy(out_buf + assembled_len, payload, (size_t)hdr.payload_len);
            assembled_len += (size_t)hdr.payload_len;
            recv_buf_consume(ctx, total);
            if (hdr.fin) { result = (int)assembled_len; goto out; } /* message complete */
            continue; /* wait for the rest of the continuation frames */
        default:
            recv_buf_consume(ctx, total);
            continue; /* BINARY etc. -- unused opcodes are ignored */
        }
    }

out:
    pthread_mutex_unlock(&ctx->io_lock);
    return result;
}

void ws_client_close(ws_client_t *ctx)
{
    if (!ctx->connected) return;

    pthread_mutex_lock(&ctx->io_lock);
    if (!ctx->closed) send_control_locked(ctx, WS_OP_CLOSE, NULL, 0);
    SSL_shutdown(ctx->ssl);
    SSL_free(ctx->ssl);
    SSL_CTX_free(ctx->ssl_ctx);
    close(ctx->sockfd);
    ctx->connected = 0;
    ctx->ssl = NULL;
    pthread_mutex_unlock(&ctx->io_lock);

    pthread_mutex_destroy(&ctx->io_lock);
}

void ws_client_shutdown(ws_client_t *ctx)
{
    if (ctx->connected) shutdown(ctx->sockfd, SHUT_RD);
}
