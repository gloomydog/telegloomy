#include "app.h"
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define APP_CHAT       1
#define APP_FILE_OFFER 2
#define APP_FILE_CHUNK 3
#define APP_BYE        4
#define CHUNK          1000
#define MAX_FILES      4

static void p32(uint8_t*b,uint32_t v){b[0]=v>>24;b[1]=v>>16;b[2]=v>>8;b[3]=v;}
static void p64(uint8_t*b,uint64_t v){for(int i=0;i<8;i++)b[i]=(uint8_t)(v>>(56-8*i));}
static uint32_t g32(const uint8_t*b){return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];}
static uint64_t g64(const uint8_t*b){uint64_t v=0;for(int i=0;i<8;i++)v=(v<<8)|b[i];return v;}

struct out_file { int used; uint32_t id; uint8_t *data; uint64_t total; uint32_t nchunks, next; int offered; uint8_t hash[32]; char name[256]; };
struct in_file  { int used, done; uint32_t id; uint8_t *data; uint64_t total, got; uint8_t hash[32]; char name[256]; };

struct app {
    transport_t *t;
    app_chat_cb on_chat; app_file_cb on_file; app_bye_cb on_bye; void *user;
    uint32_t next_id;
    struct out_file out[MAX_FILES];
    struct in_file  in[MAX_FILES];
};

static struct in_file *in_find(app_t *a, uint32_t id){ for(int i=0;i<MAX_FILES;i++) if(a->in[i].used&&a->in[i].id==id) return &a->in[i]; return NULL; }

/* Peer-supplied filenames are untrusted: collapse to a bare basename so a
 * received name can never carry a path separator or climb directories when a
 * caller turns it into an output path. */
static void sanitize_name(char *name){
    char *base=name;
    for (char *s=name; *s; s++) if (*s=='/'||*s=='\\') base=s+1;   /* keep last component */
    if (base!=name) memmove(name, base, strlen(base)+1);
    if (name[0]==0 || strcmp(name,".")==0 || strcmp(name,"..")==0) strcpy(name,"file");
}

static void on_reliable(void *u, const uint8_t *d, size_t len){
    app_t *a=u; if(len<1) return;
    if (d[0]==APP_BYE){ if(a->on_bye) a->on_bye(a->user); return; }
    if (d[0]==APP_CHAT){ if(a->on_chat) a->on_chat(a->user,(const char*)d+1,len-1); return; }
    if (d[0]==APP_FILE_OFFER){
        if (len<1+4+8+4+32) return;
        uint32_t id=g32(d+1); uint64_t total=g64(d+5); /*uint32_t cs=g32(d+13);*/
        const uint8_t *hash=d+17; const char *name=(const char*)d+49; size_t nlen=len-49;
        if (total>APP_MAX_FILE) return;              /* implausible size: don't allocate for it */
        if (in_find(a,id)) return;                    /* ignore a duplicate offer for the same id */
        for(int i=0;i<MAX_FILES;i++) if(!a->in[i].used){ struct in_file*f=&a->in[i];
            uint8_t *buf=malloc(total?total:1);
            if(!buf) return;                          /* out of memory: drop the offer, stay alive */
            f->used=1; f->done=0; f->id=id; f->total=total; f->got=0; f->data=buf;
            memcpy(f->hash,hash,32); if(nlen>255){nlen=255;} memcpy(f->name,name,nlen); f->name[nlen]=0;
            sanitize_name(f->name);
            if(a->on_file) a->on_file(a->user,id,f->name,0,total,0,0);
            break;
        }
        return;
    }
    if (d[0]==APP_FILE_CHUNK){
        if (len<9) { return; } uint32_t id=g32(d+1), idx=g32(d+5); const uint8_t*data=d+9; size_t dlen=len-9;
        struct in_file*f=in_find(a,id); if(!f||f->done) return;
        uint64_t off=(uint64_t)idx*CHUNK; if(off+dlen>f->total) dlen=f->total>off?f->total-off:0;
        memcpy(f->data+off,data,dlen); f->got+=dlen;
        if (f->got>=f->total){ uint8_t h[32]; crypto_generichash(h,32,f->data,f->total,NULL,0);
            int ok=sodium_memcmp(h,f->hash,32)==0; f->done=1;
            if(a->on_file) a->on_file(a->user,id,f->name,f->got,f->total,1,ok); }
        else if(a->on_file) a->on_file(a->user,id,f->name,f->got,f->total,0,0);
        return;
    }
}

app_t *app_new(transport_t *t, app_chat_cb oc, app_file_cb of, void *user){
    app_t *a=calloc(1,sizeof *a); if(!a) return NULL;
    a->t=t; a->on_chat=oc; a->on_file=of; a->user=user; a->next_id=1;
    transport_set_callbacks(t,on_reliable,NULL,a);
    return a;
}
void app_free(app_t *a){ if(!a)return; for(int i=0;i<MAX_FILES;i++){ free(a->out[i].data); free(a->in[i].data);} free(a); }

int app_send_chat(app_t *a,const char *text,size_t len){
    if (len>TR_MAXMSG-1) return -1;
    uint8_t m[1+TR_MAXMSG]; m[0]=APP_CHAT; memcpy(m+1,text,len);
    return transport_send_reliable(a->t,m,len+1);
}

int app_send_bye(app_t *a){ uint8_t m=APP_BYE; return transport_send_reliable(a->t,&m,1); }
void app_set_on_bye(app_t *a, app_bye_cb cb){ a->on_bye=cb; }

int64_t app_send_file(app_t *a,const char *name,const uint8_t *data,size_t len){
    int s=-1; for(int i=0;i<MAX_FILES;i++) if(!a->out[i].used){s=i;break;} if(s<0) return -1;
    struct out_file*f=&a->out[s]; f->used=1; f->id=a->next_id++; f->total=len; f->next=0; f->offered=0;
    f->nchunks=(uint32_t)((len+CHUNK-1)/CHUNK); f->data=malloc(len?len:1); memcpy(f->data,data,len);
    crypto_generichash(f->hash,32,data,len,NULL,0);
    size_t nl=strlen(name); if(nl>255)nl=255; memcpy(f->name,name,nl); f->name[nl]=0;
    return f->id;
}

const uint8_t *app_inbound_data(app_t *a,uint32_t id,uint64_t *len){
    struct in_file*f=in_find(a,id); if(!f||!f->done) return NULL; if(len)*len=f->total; return f->data;
}

static void feed(app_t *a){
    for(int i=0;i<MAX_FILES;i++){ struct out_file*f=&a->out[i]; if(!f->used) continue;
        if(!f->offered){ uint8_t m[1+4+8+4+32+256]; size_t nl=strlen(f->name); m[0]=APP_FILE_OFFER;
            p32(m+1,f->id); p64(m+5,f->total); p32(m+13,CHUNK); memcpy(m+17,f->hash,32); memcpy(m+49,f->name,nl);
            if(transport_send_reliable(a->t,m,49+nl)!=0) { continue; } f->offered=1; }
        while(f->next<f->nchunks){ uint64_t off=(uint64_t)f->next*CHUNK; size_t dl=f->total-off; if(dl>CHUNK){dl=CHUNK;}
            uint8_t m[9+CHUNK]; m[0]=APP_FILE_CHUNK; p32(m+1,f->id); p32(m+5,f->next); memcpy(m+9,f->data+off,dl);
            if(transport_send_reliable(a->t,m,9+dl)!=0) break;   /* window full: retry next poll */
            f->next++; }
        if(f->offered && f->next>=f->nchunks){ free(f->data); f->data=NULL; f->used=0; }  /* handed to transport */
    }
}

void app_poll(app_t *a,int timeout_ms){ feed(a); transport_poll(a->t,timeout_ms); feed(a); }
