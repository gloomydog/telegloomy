#pragma once
#include "transport.h"
#include <stdint.h>
#include <stddef.h>

/* Upper bound on a single transfer. Bounds both the local read in /file and the
 * allocation a *peer* can request via a FILE_OFFER, so a malicious offer can't
 * exhaust memory. */
#define APP_MAX_FILE (2ULL * 1024 * 1024 * 1024)   /* 2 GiB */

typedef struct app app_t;

typedef void (*app_chat_cb)(void *user, const char *text, size_t len);
typedef void (*app_bye_cb)(void *user);   /* peer sent an explicit disconnect */
/* done=1 when transfer completes; ok=1 if hash verified. */
typedef void (*app_file_cb)(void *user, uint32_t file_id, const char *name,
                            uint64_t received, uint64_t total, int done, int ok);

app_t *app_new(transport_t *t, app_chat_cb on_chat, app_file_cb on_file, void *user);
void   app_free(app_t *a);

int      app_send_chat(app_t *a, const char *text, size_t len);
int      app_send_bye(app_t *a);              /* tell the peer we are leaving */
void     app_set_on_bye(app_t *a, app_bye_cb cb);
/* Copies data; streams it with backpressure. Returns file_id or -1. */
int64_t  app_send_file(app_t *a, const char *name, const uint8_t *data, size_t len);

/* Retrieve a completed inbound file's bytes (valid until app_free). */
const uint8_t *app_inbound_data(app_t *a, uint32_t file_id, uint64_t *len);

void app_poll(app_t *a, int timeout_ms);   /* pump transport + feed file chunks */
