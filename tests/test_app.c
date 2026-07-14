#include "app.h"
#include "net.h"
#include "keys.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sodium.h>

#define FSIZE (200*1024)   /* 200 KB file */

struct sink {
    char last_chat[256]; int chat_count;
    int file_done, file_ok; uint32_t file_id;
};

static void on_chat(void *u,const char *t,size_t len){
    struct sink*s=u; if(len>255)len=255; memcpy(s->last_chat,t,len); s->last_chat[len]=0; s->chat_count++;
    printf("  [chat] \"%s\"\n", s->last_chat);
}
static void on_file(void *u,uint32_t id,const char *name,uint64_t recv,uint64_t total,int done,int ok){
    struct sink*s=u;
    if(done){ s->file_done=1; s->file_ok=ok; s->file_id=id;
        printf("  [file] \"%s\" complete: %llu/%llu bytes, hash %s\n", name,
               (unsigned long long)recv,(unsigned long long)total, ok?"OK":"MISMATCH"); }
}

int main(void){
    if(sodium_init()<0) return 1;
    ep_t ea,eb; int fda=udp_bind(4,&ea), fdb=udp_bind(4,&eb);
    struct sockaddr_storage sa,sb; socklen_t la=ep_to_sockaddr(&ea,&sa),lb=ep_to_sockaddr(&eb,&sb);
    connect(fda,(struct sockaddr*)&sb,lb); connect(fdb,(struct sockaddr*)&sa,la);

    uint8_t K[32]; randombytes_buf(K,sizeof K);
    transport_t *TA=transport_new(fda,0,K,NULL,NULL,NULL);
    transport_t *TB=transport_new(fdb,1,K,NULL,NULL,NULL);
    transport_set_drop(TA,15); transport_set_drop(TB,15);
    struct sink sb_={0};
    app_t *A=app_new(TA,NULL,NULL,NULL);            /* A only sends */
    app_t *B=app_new(TB,on_chat,on_file,&sb_);      /* B receives   */
    printf("link: 15%% loss both ways; sending chat + a %d KB file A->B\n", FSIZE/1024);

    /* make a random file and remember it to verify byte-for-byte */
    uint8_t *orig=malloc(FSIZE); randombytes_buf(orig,FSIZE);

    app_send_chat(A,"hello over p2p",14);
    int64_t fid=app_send_file(A,"secret.bin",orig,FSIZE);
    app_send_chat(A,"file is on the way",18);

    long guard=0;
    while(!sb_.file_done && guard<30000){ app_poll(A,3); app_poll(B,3); guard+=6; }

    if(sb_.chat_count<2){ fprintf(stderr,"FAIL: chats delivered=%d\n",sb_.chat_count); return 1; }
    if(!sb_.file_done||!sb_.file_ok){ fprintf(stderr,"FAIL: file done=%d ok=%d\n",sb_.file_done,sb_.file_ok); return 1; }

    uint64_t rlen=0; const uint8_t*rd=app_inbound_data(B,(uint32_t)fid,&rlen);
    if(!rd||rlen!=FSIZE||memcmp(rd,orig,FSIZE)!=0){ fprintf(stderr,"FAIL: reassembled bytes differ\n"); return 1; }
    printf("  byte-for-byte identical (%llu bytes)\n",(unsigned long long)rlen);

    free(orig); app_free(A); app_free(B); transport_free(TA); transport_free(TB); close(fda); close(fdb);
    printf("\nall tests passed.\n");
    return 0;
}
