/* Mutation fuzzer for every attacker-controlled parser, run under ASAN+UBSAN.
 * Not coverage-guided, but exercises the length/bounds handling that matters. */
#include "candidate.h"
#include "transport.h"
#include "keys.h"
#include "envelope.h"
#include "nostr_event.h"
#include "ws_frame.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#define KINDV 20077
#define MAXIN 9000

/* ---- seeds (built from real data) ---- */
static uint8_t seed_candwire[512]; static size_t seed_candwire_len;
static uint8_t seed_sealed[600];   static size_t seed_sealed_len;
static uint8_t seed_wire[1100];    static size_t seed_wire_len;
static char    seed_env[9000];     static size_t seed_env_len;
static char    seed_evt[9000];     static size_t seed_evt_len;
static uint8_t seed_ws[64];        static size_t seed_ws_len;

static uint8_t sk[32];
static transport_t *rxT;
static uint8_t cap_wire[1100]; static size_t cap_len;
static int cap_send(void *u,const uint8_t*w,size_t n){(void)u; if(n<=sizeof cap_wire){memcpy(cap_wire,w,n);cap_len=n;} return 0;}
static void noop_rel(void*u,const uint8_t*d,size_t n){(void)u;(void)d;(void)n;}

static size_t mutate(const uint8_t*seed,size_t slen,uint8_t*out,size_t outcap){
    int mode=rand()%4;
    if(mode==0){ size_t n=rand()%(outcap+1); for(size_t i=0;i<n;i++)out[i]=rand()&0xff; return n; }
    size_t n=slen; if(n>outcap)n=outcap; memcpy(out,seed,n);
    if(mode==1){ int k=1+rand()%8; for(int i=0;i<k&&n;i++) out[rand()%n]^=(uint8_t)(1<<(rand()%8)); }
    else if(mode==2){ n = n? (size_t)(rand()%(int)n):0; }
    else { size_t add=rand()%(outcap-n+1); for(size_t i=0;i<add;i++)out[n+i]=rand()&0xff; n+=add; }
    return n;
}

static void build_seeds(void){
    /* candidate wire */
    candidate_t c[3]; memset(c,0,sizeof c);
    c[0].type=CAND_HOST; c[0].ep.family=4; c[0].ep.port=1234; c[0].ep.addr[0]=192;c[0].ep.addr[1]=168;c[0].ep.addr[2]=1;c[0].ep.addr[3]=5;
    c[1].type=CAND_SRFLX; c[1].ep.family=6; c[1].ep.port=5678; for(int i=0;i<16;i++)c[1].ep.addr[i]=i;
    seed_candwire_len=(size_t)cand_serialize(c,2,seed_candwire,sizeof seed_candwire);
    /* sealed candidate blob */
    randombytes_buf(sk,sizeof sk);
    cand_seal(sk,seed_candwire,seed_candwire_len,seed_sealed,&seed_sealed_len);
    /* transport wire: capture a real reliable packet */
    uint8_t K[32]; randombytes_buf(K,sizeof K);
    transport_t*txT=transport_new(-1,0,K,noop_rel,noop_rel,NULL);
    transport_set_relay(txT,cap_send,NULL);
    transport_send_reliable(txT,(const uint8_t*)"hello world",11);
    memcpy(seed_wire,cap_wire,cap_len); seed_wire_len=cap_len;
    rxT=transport_new(-1,1,K,noop_rel,noop_rel,NULL);  /* receiver for inject fuzzing */
    transport_free(txT);
    /* envelope JSON */
    uint8_t data[64]; for(int i=0;i<64;i++)data[i]=i;
    char room[33]; sodium_bin2hex(room,sizeof room,(unsigned char*)"0123456789abcdef",16);
    int el=envelope_build(seed_env,sizeof seed_env,room,ENVELOPE_MSG,"",data,sizeof data);
    seed_env_len = el>0?(size_t)el:0;
    /* full nostr EVENT message */
    nostr_identity_t id;
    if(nostr_identity_generate(&id)==0){
        char ev[9000];
        if(nostr_build_event(&id,KINDV,room,seed_env,ev,sizeof ev)>=0){
            int ml=nostr_wrap_event_msg(ev,seed_evt,sizeof seed_evt);
            seed_evt_len = ml>0?(size_t)ml:0;
        }
    }
    /* ws frame */
    uint8_t f[]={0x81,0x05,'h','e','l','l','o'}; memcpy(seed_ws,f,sizeof f); seed_ws_len=sizeof f;
}

int main(int argc,char**argv){
    if(sodium_init()<0) return 1;
    unsigned long iters = argc>1?strtoul(argv[1],0,10):300000;
    srand(argc>2?(unsigned)strtoul(argv[2],0,10):(unsigned)time(0));
    build_seeds();

    uint8_t in[MAXIN+1]; uint8_t out[MAXIN+64]; size_t olen;
    for(unsigned long it=0; it<iters; it++){
        int tgt = it % 6;
        switch(tgt){
        case 0: { size_t n=mutate(seed_candwire,seed_candwire_len,in,600);
                  candidate_t o[MAX_CANDS]; cand_deserialize(in,n,o,MAX_CANDS); } break;
        case 1: { size_t n=mutate(seed_sealed,seed_sealed_len,in,600);
                  cand_open(sk,in,n,out,&olen); } break;
        case 2: { size_t n=mutate(seed_wire,seed_wire_len,in,1100);
                  transport_inject(rxT,in,n); } break;
        case 3: { size_t n=mutate(seed_ws,seed_ws_len,in,64);
                  ws_frame_header_t h; ws_parse_frame_header(in,n,&h); } break;
        case 4: { size_t n=mutate((uint8_t*)seed_env,seed_env_len,in,MAXIN); in[n]=0;
                  envelope_t e; envelope_parse((char*)in,&e); } break;
        case 5: { size_t n=mutate((uint8_t*)seed_evt,seed_evt_len,in,MAXIN); in[n]=0;
                  char pub[65],content[9000]; nostr_parse_incoming((char*)in,pub,sizeof pub,content,sizeof content); } break;
        }
    }
    transport_free(rxT);
    printf("fuzz: %lu iterations across 6 parsers, no ASAN/UBSAN abort.\n", iters);
    return 0;
}
