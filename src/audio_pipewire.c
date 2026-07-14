#include "audio_pipewire.h"
#include <string.h>
#include <signal.h>
#include <pipewire/pipewire.h>
#include <spa/param/audio/format-utils.h>
#include <spa/pod/builder.h>
#include <spa/utils/defs.h>

#define RING 16384

struct pw_audio {
    struct pw_main_loop *loop;
    struct pw_stream *capture, *playback;
    voice_t *v; int fs;
    int16_t acc[8192]; int acc_n;          /* capture: re-chunk to fs frames */
    int16_t ring[RING]; int rhead, rlen;   /* playback: decoded PCM, quantum-agnostic */
};

static struct pw_audio *g_self;

static void on_capture_process(void *userdata) {
    struct pw_audio *d = userdata;
    struct pw_buffer *b = pw_stream_dequeue_buffer(d->capture);
    if (!b) return;
    struct spa_buffer *buf = b->buffer;
    int16_t *s = buf->datas[0].data;
    if (s && buf->datas[0].chunk) {
        uint32_t n = buf->datas[0].chunk->size / sizeof(int16_t);
        for (uint32_t i = 0; i < n; i++) {
            d->acc[d->acc_n++] = s[i];
            if (d->acc_n == d->fs) { voice_capture_frame(d->v, d->acc, d->fs); d->acc_n = 0; }
        }
    }
    pw_stream_queue_buffer(d->capture, b);
}

static void on_playback_process(void *userdata) {
    struct pw_audio *d = userdata;
    struct pw_buffer *b = pw_stream_dequeue_buffer(d->playback);
    if (!b) return;
    struct spa_buffer *buf = b->buffer;
    int16_t *dst = buf->datas[0].data;
    if (!dst) { pw_stream_queue_buffer(d->playback, b); return; }
    int stride = sizeof(int16_t);
    int maxframes = (int)(buf->datas[0].maxsize / stride);
    int want = b->requested ? (int)b->requested : maxframes;   /* frames the graph wants */
    if (want > maxframes) want = maxframes;

    int w = 0;
    while (w < want) {
        if (d->rlen == 0) {                 /* refill: decode one 20 ms frame */
            int16_t fr[1024]; int concealed = 0;
            int got = voice_playout_frame(d->v, fr, d->fs, &concealed);
            int n = got > 0 ? got : d->fs;
            if (got <= 0) memset(fr, 0, sizeof(int16_t) * d->fs);   /* silence until primed */
            if (n > RING) n = RING;
            for (int i = 0; i < n; i++) {
                d->ring[(d->rhead + d->rlen) % RING] = fr[i];
                if (d->rlen < RING) d->rlen++; else d->rhead = (d->rhead + 1) % RING;
            }
        }
        int take = want - w; if (take > d->rlen) take = d->rlen;
        if (take == 0) break;
        for (int i = 0; i < take; i++) { dst[w++] = d->ring[d->rhead]; d->rhead = (d->rhead + 1) % RING; d->rlen--; }
    }
    buf->datas[0].chunk->offset = 0;
    buf->datas[0].chunk->stride = stride;
    buf->datas[0].chunk->size   = (uint32_t)w * stride;
    pw_stream_queue_buffer(d->playback, b);
}

static const struct pw_stream_events capture_events = {
    PW_VERSION_STREAM_EVENTS, .process = on_capture_process,
};
static const struct pw_stream_events playback_events = {
    PW_VERSION_STREAM_EVENTS, .process = on_playback_process,
};

static void on_sigint(int sig) { (void)sig; if (g_self) pw_main_loop_quit(g_self->loop); }
void audio_pw_quit(void) { if (g_self && g_self->loop) pw_main_loop_quit(g_self->loop); }

static struct pw_stream *make_stream(struct pw_audio *d, const char *name, const char *category,
                                     enum pw_direction dir, const struct pw_stream_events *ev, int sr) {
    struct pw_properties *props = pw_properties_new(
        PW_KEY_MEDIA_TYPE, "Audio", PW_KEY_MEDIA_CATEGORY, category,
        PW_KEY_MEDIA_ROLE, "Communication", PW_KEY_NODE_LATENCY, "480/48000", NULL);
    struct pw_stream *st = pw_stream_new_simple(pw_main_loop_get_loop(d->loop), name, props, ev, d);
    if (!st) return NULL;
    uint8_t buffer[1024];
    struct spa_pod_builder bld = SPA_POD_BUILDER_INIT(buffer, sizeof buffer);
    struct spa_audio_info_raw info = { .format = SPA_AUDIO_FORMAT_S16,
        .rate = (uint32_t)sr, .channels = 1 };
    const struct spa_pod *params[1] = { spa_format_audio_raw_build(&bld, SPA_PARAM_EnumFormat, &info) };
    pw_stream_connect(st, dir, PW_ID_ANY,
        PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_RT_PROCESS,
        params, 1);
    return st;
}

int audio_pw_run(voice_t *v, int sr, int fs) {
    struct pw_audio d; memset(&d, 0, sizeof d);
    d.v = v; d.fs = fs;
    g_self = &d;
    pw_init(NULL, NULL);
    d.loop = pw_main_loop_new(NULL);
    if (!d.loop) return -1;
    signal(SIGINT, on_sigint);
    d.capture  = make_stream(&d, "telegloomy-voice-cap",  "Capture",  PW_DIRECTION_INPUT,  &capture_events,  sr);
    d.playback = make_stream(&d, "telegloomy-voice-play", "Playback", PW_DIRECTION_OUTPUT, &playback_events, sr);
    if (!d.capture || !d.playback) return -1;
    pw_main_loop_run(d.loop);
    g_self = NULL;
    pw_stream_destroy(d.capture); pw_stream_destroy(d.playback);
    pw_main_loop_destroy(d.loop);
    pw_deinit();
    return 0;
}
