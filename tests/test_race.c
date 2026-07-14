/* Concurrency check (run under ThreadSanitizer): the transport send path and
 * the voice jitter buffer are each touched by two threads. */
#include "transport.h"
#include "voice.h"
#include "net.h"
#include "keys.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sodium.h>
#include <stdatomic.h>

static transport_t *A, *B;

static void noop(void*u,const uint8_t*d,size_t n){(void)u;(void)d;(void)n;}

/* voice thread: many unreliable sends (-> send_pkt, shared tx counter) */
static void *voice_tx(void *arg){ (void)arg;
    uint8_t m[40]; memset(m,7,sizeof m);
    for(int i=0;i<60000;i++) transport_send_unreliable(A,m,sizeof m);
    return NULL;
}
/* main thread: reliable sends + poll (retransmit -> send_pkt) concurrently */
static void main_tx(void){
    uint8_t m[40]; memset(m,9,sizeof m);
    for(int i=0;i<60000;i++){ transport_send_reliable(A,m,sizeof m); transport_poll(A,0); transport_poll(B,0); }
}

static voice_t *V;
static _Atomic int stop_v;
static void *voice_writer(void *arg){ (void)arg;
    uint8_t pkt[64]; for(int i=0;i<4;i++) pkt[i]=0; memset(pkt+4,3,60);
    for(uint32_t seq=0; seq<40000; seq++){ pkt[0]=seq>>24;pkt[1]=seq>>16;pkt[2]=seq>>8;pkt[3]=seq; voice_on_packet(V,pkt,64); }
    stop_v=1; return NULL;
}

int main(void){
    if(sodium_init()<0) return 1;
    /* --- transport send-path race --- */
    ep_t ea,eb; int fda=udp_bind(4,&ea), fdb=udp_bind(4,&eb);
    struct sockaddr_storage sa,sb; socklen_t la=ep_to_sockaddr(&ea,&sa),lb=ep_to_sockaddr(&eb,&sb);
    connect(fda,(struct sockaddr*)&sb,lb); connect(fdb,(struct sockaddr*)&sa,la);
    uint8_t K[32]; randombytes_buf(K,sizeof K);
    A=transport_new(fda,0,K,noop,noop,NULL); B=transport_new(fdb,1,K,noop,noop,NULL);
    pthread_t vt; pthread_create(&vt,NULL,voice_tx,NULL);
    main_tx();
    pthread_join(vt,NULL);
    printf("transport send-path: exercised concurrently\n");

    /* --- voice jitter-buffer race --- */
    V=voice_new(NULL,48000,960);
    pthread_t wr; pthread_create(&wr,NULL,voice_writer,NULL);
    int16_t pcm[960]; int c;
    while(!stop_v){ voice_playout_frame(V,pcm,960,&c); }
    for(int i=0;i<100;i++) voice_playout_frame(V,pcm,960,&c);
    pthread_join(wr,NULL);
    voice_free(V);
    printf("voice jitter-buffer: exercised concurrently\n\ndone.\n");
    transport_free(A); transport_free(B);
    return 0;
}
