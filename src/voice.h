#pragma once
#include "transport.h"
#include <stdint.h>

typedef struct voice voice_t;

/* 48 kHz mono, frame_samples typically 960 (20 ms). */
voice_t *voice_new(transport_t *t, int sample_rate, int frame_samples);
void     voice_free(voice_t *v);

/* Capture side: encode one PCM frame and send it on the unreliable channel. */
int voice_capture_frame(voice_t *v, const int16_t *pcm, int nsamples);

/* Transport unreliable callback (matches tr_recv_cb): feeds the jitter buffer. */
void voice_on_packet(void *user, const uint8_t *data, size_t len);

/* Playout side: produce the next PCM frame from the jitter buffer, using
 * Opus PLC to conceal missing frames. *concealed set to 1 if PLC was used.
 * Returns samples written, or 0 if not yet primed. */
int voice_playout_frame(voice_t *v, int16_t *pcm, int nsamples, int *concealed);
