#pragma once
#include "voice.h"
/* Run PipeWire capture+playback, driving the voice module. Blocks until the
 * main loop is stopped (e.g. SIGINT). Returns 0 on clean exit.
 * Requires libpipewire-0.3. */
int audio_pw_run(voice_t *v, int sample_rate, int frame_samples);
/* Stop a running audio loop (call from another thread), so audio_pw_run returns. */
void audio_pw_quit(void);
