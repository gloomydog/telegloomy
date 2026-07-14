#include "voice.h"
#include "net.h"
#include "keys.h"
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sodium.h>

#define SR 48000
#define FS 960          /* 20 ms */
#define NFRAMES 100

static double rms(const int16_t *p, int n){ double s=0; for(int i=0;i<n;i++) s+=(double)p[i]*p[i]; return sqrt(s/n); }

int main(void){
    if (sodium_init()<0) return 1;
    ep_t ea,eb; int fda=udp_bind(4,&ea), fdb=udp_bind(4,&eb);
    struct sockaddr_storage sa,sb; socklen_t la=ep_to_sockaddr(&ea,&sa),lb=ep_to_sockaddr(&eb,&sb);
    connect(fda,(struct sockaddr*)&sb,lb); connect(fdb,(struct sockaddr*)&sa,la);

    uint8_t K[32]; randombytes_buf(K,sizeof K);
    transport_t *TA=transport_new(fda,0,K,NULL,NULL,NULL);
    transport_t *TB=transport_new(fdb,1,K,NULL,NULL,NULL);
    transport_set_drop(TA,15);                  /* 15% loss A->B */

    voice_t *VA=voice_new(TA,SR,FS), *VB=voice_new(TB,SR,FS);
    transport_set_callbacks(TB,NULL,voice_on_packet,VB);   /* B decodes */
    printf("voice: 48kHz mono, 20ms frames, 15%% loss A->B\n");

    /* 440 Hz sine, amplitude 8000 */
    int16_t in[FS]; double phase=0, dp=2*M_PI*440.0/SR;
    double in_rms_sum=0; int real=0, plc=0; double out_rms_real_sum=0;

    for (int f=0; f<NFRAMES; f++){
        for (int i=0;i<FS;i++){ in[i]=(int16_t)(8000*sin(phase)); phase+=dp; }
        in_rms_sum += rms(in,FS);
        voice_capture_frame(VA,in,FS);
        transport_poll(TA,1); transport_poll(TB,1);
        int16_t out[FS]; int concealed=0;
        if (voice_playout_frame(VB,out,FS,&concealed)==FS){
            if (concealed) plc++; else { real++; out_rms_real_sum += rms(out,FS); }
        }
    }
    /* drain remaining buffered frames */
    for (int i=0;i<8;i++){ int16_t out[FS]; int c=0; if(voice_playout_frame(VB,out,FS,&c)==FS){ if(c)plc++; else{real++; out_rms_real_sum+=rms(out,FS);} } }

    double in_rms = in_rms_sum/NFRAMES;
    double out_rms = real? out_rms_real_sum/real : 0;
    printf("frames sent=%d | decoded_real=%d concealed(PLC)=%d\n", NFRAMES, real, plc);
    printf("input RMS=%.0f  output RMS (real frames)=%.0f  ratio=%.2f\n", in_rms, out_rms, out_rms/in_rms);

    if (real==0){ fprintf(stderr,"FAIL: no frames decoded\n"); return 1; }
    if (plc==0){ fprintf(stderr,"FAIL: expected some loss/PLC\n"); return 1; }
    if (out_rms < 0.25*in_rms || out_rms > 4.0*in_rms){ fprintf(stderr,"FAIL: decoded energy off (silence/garbage)\n"); return 1; }
    printf("  -> real audio round-tripped through Opus; PLC concealed the %d lost frames\n", plc);

    voice_free(VA); voice_free(VB); transport_free(TA); transport_free(TB);
    printf("\nall tests passed.\n");
    return 0;
}
