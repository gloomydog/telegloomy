#include "transport.h"
#include "net.h"
#include "keys.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sodium.h>

#define N_REL   100
#define N_UNREL 100
#define MARK 0xDEADBEEFu

struct sink { uint32_t rel_expect; int rel_ok, rel_bad; int unrel_ok, unrel_bad; };

static void put32(uint8_t*p,uint32_t v){p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v;}
static uint32_t get32(const uint8_t*p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}

static void on_rel(void *u, const uint8_t *d, size_t len){
    struct sink *s=u;
    if (len==8 && get32(d)==s->rel_expect && get32(d+4)==MARK){ s->rel_ok++; s->rel_expect++; }
    else s->rel_bad++;                     /* out of order or corrupt = failure */
}
static void on_unrel(void *u, const uint8_t *d, size_t len){
    struct sink *s=u;
    if (len==8 && get32(d+4)==MARK) s->unrel_ok++;   /* order not guaranteed; just check integrity+index */
    else s->unrel_bad++;
}

int main(void){
    if (sodium_init()<0) return 1;
    ep_t ea,eb; int fda=udp_bind(4,&ea), fdb=udp_bind(4,&eb);
    struct sockaddr_storage sa,sb; socklen_t la=ep_to_sockaddr(&ea,&sa), lb=ep_to_sockaddr(&eb,&sb);
    connect(fda,(struct sockaddr*)&sb,lb); connect(fdb,(struct sockaddr*)&sa,la);

    uint8_t K[32]; randombytes_buf(K,sizeof K);
    struct sink sink_b={0}, sink_a={0};
    transport_t *A=transport_new(fda,0,K,on_rel,on_unrel,&sink_a);
    transport_t *B=transport_new(fdb,1,K,on_rel,on_unrel,&sink_b);
    transport_set_drop(A,20); transport_set_drop(B,20);   /* 20% loss each way */
    printf("link: 20%% packet loss both directions\n");

    /* Reliable: A -> B, N_REL messages, must all arrive in order despite loss. */
    uint32_t sent=0; long guard=0;
    while ((sent<N_REL || transport_reliable_inflight(A)>0 || sink_b.rel_ok<N_REL) && guard<20000){
        while (sent<N_REL){
            uint8_t m[8]; put32(m,sent); put32(m+4,MARK);
            if (transport_send_reliable(A,m,8)!=0) break;
            sent++;
        }
        transport_poll(A,5); transport_poll(B,5); guard+=10;
    }
    printf("reliable: sent=%u delivered_in_order=%d bad=%d inflight=%d\n",
           sent, sink_b.rel_ok, sink_b.rel_bad, transport_reliable_inflight(A));
    if (sink_b.rel_ok!=N_REL || sink_b.rel_bad!=0){ fprintf(stderr,"RELIABLE FAILED\n"); return 1; }

    /* Unreliable: A -> B, fire N_UNREL, expect a lossy subset, all intact. */
    for (uint32_t i=0;i<N_UNREL;i++){ uint8_t m[8]; put32(m,i); put32(m+4,MARK);
        transport_send_unreliable(A,m,8); transport_poll(B,0); }
    for (int i=0;i<50;i++){ transport_poll(B,2); }   /* drain */
    printf("unreliable: sent=%d received=%d corrupt=%d\n", N_UNREL, sink_b.unrel_ok, sink_b.unrel_bad);
    if (sink_b.unrel_bad!=0){ fprintf(stderr,"UNRELIABLE corrupt frame\n"); return 1; }
    if (sink_b.unrel_ok==0 || sink_b.unrel_ok==N_UNREL){ fprintf(stderr,"expected a lossy subset, got %d\n", sink_b.unrel_ok); return 1; }

    printf("  -> reliable channel repaired all loss; unreliable dropped %d as designed\n", N_UNREL-sink_b.unrel_ok);
    transport_free(A); transport_free(B); close(fda); close(fdb);
    printf("\nall tests passed.\n");
    return 0;
}
