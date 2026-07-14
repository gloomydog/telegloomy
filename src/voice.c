#include "voice.h"
#include <stdlib.h>
#include <string.h>
#include <opus/opus.h>
#include <pthread.h>
#include <math.h>

#define JBUF   48
#define MAXPKT 512
#define TARGET 3        /* jitter depth before playout starts (~60 ms) */

static void p32(uint8_t*b,uint32_t v){b[0]=v>>24;b[1]=v>>16;b[2]=v>>8;b[3]=v;}
static uint32_t g32(const uint8_t*b){return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];}

struct slot { int have; uint32_t seq; int len; uint8_t data[MAXPKT]; };

struct voice {
    transport_t *t;
    OpusEncoder *enc; OpusDecoder *dec;
    int sr, fs;
    uint32_t tx_seq;
    struct slot jb[JBUF];
    uint32_t play_seq; int primed; int buffered;
    pthread_mutex_t jbl;
};

voice_t *voice_new(transport_t *t, int sr, int fs) {
    int err;
    voice_t *v = calloc(1, sizeof *v);
    if (!v) return NULL;
    v->t = t; v->sr = sr; v->fs = fs;
    v->enc = opus_encoder_create(sr, 1, OPUS_APPLICATION_VOIP, &err);
    if (err != OPUS_OK) { free(v); return NULL; }
    v->dec = opus_decoder_create(sr, 1, &err);
    if (err != OPUS_OK) { opus_encoder_destroy(v->enc); free(v); return NULL; }
    opus_encoder_ctl(v->enc, OPUS_SET_BITRATE(24000));
    opus_encoder_ctl(v->enc, OPUS_SET_INBAND_FEC(1));
    opus_encoder_ctl(v->enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
    opus_encoder_ctl(v->enc, OPUS_SET_DTX(1));
    pthread_mutex_init(&v->jbl, NULL);
    return v;
}

void voice_free(voice_t *v) {
    if (!v) return;
    if (v->enc) opus_encoder_destroy(v->enc);
    if (v->dec) opus_decoder_destroy(v->dec);
    pthread_mutex_destroy(&v->jbl);
    free(v);
}

#define GATE_RMS 220.0   /* below this, treat the frame as background noise */
int voice_capture_frame(voice_t *v, const int16_t *pcm, int n) {
    if (n != v->fs) return -1;
    /* Simple noise gate: silence sub-threshold frames so ambient hiss during
     * pauses is not transmitted (with DTX this sends almost nothing). */
    double e = 0; for (int i = 0; i < n; i++) e += (double)pcm[i] * pcm[i];
    double rms = sqrt(e / n);
    const int16_t *src = pcm;
    int16_t gated[1024];
    if (rms < GATE_RMS && n <= 1024) { memset(gated, 0, sizeof(int16_t) * n); src = gated; }
    uint8_t frame[MAXPKT];
    int nb = opus_encode(v->enc, src, n, frame, sizeof frame);
    if (nb < 0) return -1;
    uint8_t pkt[4 + MAXPKT]; p32(pkt, v->tx_seq++); memcpy(pkt+4, frame, nb);
    return transport_send_unreliable(v->t, pkt, 4 + nb);
}

void voice_on_packet(void *user, const uint8_t *data, size_t len) {
    voice_t *v = user;
    if (len < 4 || len-4 > MAXPKT) return;
    pthread_mutex_lock(&v->jbl);
    uint32_t seq = g32(data);
    if (v->primed && seq < v->play_seq) { pthread_mutex_unlock(&v->jbl); return; }  /* too late */
    int k = seq % JBUF;
    if (v->jb[k].have && v->jb[k].seq == seq) { pthread_mutex_unlock(&v->jbl); return; }  /* dup */
    v->jb[k].have = 1; v->jb[k].seq = seq; v->jb[k].len = (int)(len-4);
    memcpy(v->jb[k].data, data+4, len-4);
    if (!v->primed) {
        v->buffered++;
        if (v->buffered == 1) v->play_seq = seq;         /* base = first seq seen */
        else if (seq < v->play_seq) v->play_seq = seq;
        if (v->buffered >= TARGET) v->primed = 1;
    }
    pthread_mutex_unlock(&v->jbl);
}

int voice_playout_frame(voice_t *v, int16_t *pcm, int n, int *concealed) {
    if (n != v->fs) return 0;
    pthread_mutex_lock(&v->jbl);
    if (!v->primed) { if (concealed) *concealed = 0; pthread_mutex_unlock(&v->jbl); return 0; }
    int k = v->play_seq % JBUF;
    int got;
    if (v->jb[k].have && v->jb[k].seq == v->play_seq) {
        got = opus_decode(v->dec, v->jb[k].data, v->jb[k].len, pcm, n, 0);
        v->jb[k].have = 0;
        if (concealed) *concealed = 0;
    } else {
        got = opus_decode(v->dec, NULL, 0, pcm, n, 0);   /* packet-loss concealment */
        if (concealed) *concealed = 1;
    }
    v->play_seq++;
    pthread_mutex_unlock(&v->jbl);
    return got < 0 ? 0 : got;
}
