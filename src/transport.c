#include "transport.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <endian.h>
#include <sys/socket.h>
#include <sodium.h>
#include <pthread.h>

#define CH_REL_DATA 1
#define CH_REL_ACK  2
#define CH_UNREL    3
#define RTO_MS      100
#define NB crypto_aead_chacha20poly1305_ietf_NPUBBYTES  /* 12 */
#define AB crypto_aead_chacha20poly1305_ietf_ABYTES     /* 16 */

struct out_msg { uint32_t rseq; uint16_t len; long sent; int used; uint8_t data[TR_MAXMSG]; };
struct rbuf    { int have; uint32_t rseq; uint16_t len; uint8_t data[TR_MAXMSG]; };

struct transport {
    int fd, drop_pct;
    uint8_t tx_rel[32], rx_rel[32], tx_unrel[32], rx_unrel[32];
    uint64_t tx_ctr;              /* AEAD nonce counter, starts at 1 */
    uint64_t rr_hi, rr_bits;      /* anti-replay sliding window      */
    struct out_msg out[TR_WIN];   /* reliable TX outstanding         */
    uint32_t next_rseq;
    uint32_t rcv_next;            /* reliable RX: next in-order rseq  */
    struct rbuf reorder[TR_WIN];
    tr_recv_cb on_rel, on_unrel; void *user; void *user_unrel;
    tr_send_fn send_fn; void *send_user; int relayed;
    pthread_mutex_t txlock;         /* guards only the tx nonce counter + socket write */
};
/* Threading: txlock covers just send_pkt's counter/socket, because that path is
 * the only one shared across threads (voice thread sends unreliable while the
 * main thread sends reliable). The reliable bookkeeping below -- out[], reorder[],
 * next_rseq, rcv_next, and the replay window -- is touched solely from the main
 * thread (transport_send_reliable, transport_poll, on_ack via handle_wire), so it
 * needs no lock. If a future caller ever drives reliable I/O from another thread,
 * that invariant breaks and these need their own mutex. */

static long now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000L+t.tv_nsec/1000000L; }
static void put32(uint8_t *p, uint32_t v){ p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
static uint32_t get32(const uint8_t *p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }

transport_t *transport_new(int fd, int role, const uint8_t K[32],
                           tr_recv_cb on_rel, tr_recv_cb on_unrel, void *user) {
    transport_t *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->fd = fd; t->tx_ctr = 0; t->rr_hi = 0; t->rr_bits = 0;
    t->next_rseq = 0; t->rcv_next = 0;
    t->on_rel = on_rel; t->on_unrel = on_unrel; t->user = user; t->user_unrel = user;
    pthread_mutex_init(&t->txlock, NULL);
    /* initiator sends on A2B and receives on B2A; responder mirrors */
    uint64_t tr = role==0 ? SUBKEY_REL_A2B   : SUBKEY_REL_B2A;
    uint64_t rr = role==0 ? SUBKEY_REL_B2A   : SUBKEY_REL_A2B;
    uint64_t tu = role==0 ? SUBKEY_UNREL_A2B : SUBKEY_UNREL_B2A;
    uint64_t ru = role==0 ? SUBKEY_UNREL_B2A : SUBKEY_UNREL_A2B;
    derive_subkey(t->tx_rel, tr, K);   derive_subkey(t->rx_rel, rr, K);
    derive_subkey(t->tx_unrel, tu, K); derive_subkey(t->rx_unrel, ru, K);
    return t;
}
void transport_free(transport_t *t){ if(t){ pthread_mutex_destroy(&t->txlock); sodium_memzero(t,sizeof *t); free(t);} }
void transport_set_drop(transport_t *t,int pct){ t->drop_pct=pct; }

/* encrypt one plaintext frame with the given key and send. */
static void send_pkt(transport_t *t, const uint8_t *key, const uint8_t *plain, size_t plen) {
    pthread_mutex_lock(&t->txlock);
    uint64_t ctr = ++t->tx_ctr;
    uint8_t nonce[NB]; memset(nonce,0,NB);
    uint64_t be = htobe64(ctr); memcpy(nonce+4,&be,8);
    uint8_t wire[8 + TR_MAXMSG + 16 + 8]; put32(wire, ctr>>32); put32(wire+4, ctr);
    unsigned long long clen=0;
    crypto_aead_chacha20poly1305_ietf_encrypt(wire+8,&clen, plain,plen, NULL,0, NULL, nonce, key);
    if (!(t->drop_pct && (int)(randombytes_uniform(100)) < t->drop_pct)) {  /* simulate loss */
        if (t->send_fn) t->send_fn(t->send_user, wire, 8+clen);
        else send(t->fd, wire, 8+clen, 0);
    }
    pthread_mutex_unlock(&t->txlock);
}

int transport_send_unreliable(transport_t *t, const uint8_t *data, size_t len) {
    if (len > TR_MAXMSG) return -1;
    uint8_t p[1+4+TR_MAXMSG]; p[0]=CH_UNREL; put32(p+1, 0);   /* seq field unused: voice carries its own */
    memcpy(p+5, data, len);
    send_pkt(t, t->tx_unrel, p, 5+len);
    return 0;
}

int transport_send_reliable(transport_t *t, const uint8_t *data, size_t len) {
    if (len > TR_MAXMSG) return -1;
    int slot=-1; for (int i=0;i<TR_WIN;i++) if(!t->out[i].used){slot=i;break;}
    if (slot<0) return -1;                       /* window full */
    struct out_msg *m=&t->out[slot];
    m->used=1; m->rseq=t->next_rseq++; m->len=(uint16_t)len; m->sent=now_ms();
    memcpy(m->data,data,len);
    uint8_t p[1+4+TR_MAXMSG]; p[0]=CH_REL_DATA; put32(p+1,m->rseq); memcpy(p+5,data,len);
    send_pkt(t,t->tx_rel,p,5+len);
    return 0;
}

int transport_reliable_inflight(transport_t *t){ int n=0; for(int i=0;i<TR_WIN;i++) if(t->out[i].used) n++; return n; }

static void send_ack(transport_t *t) {
    uint32_t sack=0;
    for (int i=0;i<32;i++){ uint32_t s=t->rcv_next+1+i; int k=s%TR_WIN; if(t->reorder[k].have&&t->reorder[k].rseq==s) sack|=(1u<<i); }
    uint8_t p[9]; p[0]=CH_REL_ACK; put32(p+1,t->rcv_next); put32(p+5,sack);
    send_pkt(t,t->tx_rel,p,9);
}

static void on_rel_data(transport_t *t, uint32_t rseq, const uint8_t *data, size_t len) {
    if (rseq==t->rcv_next) {
        t->on_rel(t->user,data,len); t->rcv_next++;
        for(;;){ int k=t->rcv_next%TR_WIN; if(t->reorder[k].have&&t->reorder[k].rseq==t->rcv_next){
            t->on_rel(t->user,t->reorder[k].data,t->reorder[k].len); t->reorder[k].have=0; t->rcv_next++; } else break; }
    } else if (rseq>t->rcv_next && rseq < t->rcv_next+TR_WIN) {
        int k=rseq%TR_WIN; if(!t->reorder[k].have){ t->reorder[k].have=1; t->reorder[k].rseq=rseq; t->reorder[k].len=(uint16_t)len; memcpy(t->reorder[k].data,data,len);}    }
    send_ack(t);   /* immediate ack (dup or in-order both) */
}

static void on_ack(transport_t *t, uint32_t cumack, uint32_t sack) {
    for (int i=0;i<TR_WIN;i++){ if(!t->out[i].used) continue; uint32_t s=t->out[i].rseq;
        if (s<cumack) t->out[i].used=0;
        else { uint32_t d=s-(cumack+1); if(s>cumack && d<32 && (sack&(1u<<d))) t->out[i].used=0; } }
}

static int replay_ok(transport_t *t, uint64_t ctr) {
    if (ctr>t->rr_hi){ uint64_t sh=ctr-t->rr_hi; t->rr_bits = sh>=64?0:(t->rr_bits<<sh); t->rr_bits|=1; t->rr_hi=ctr; return 1; }
    uint64_t d=t->rr_hi-ctr; if(d>=64) return 0; if(t->rr_bits&(1ull<<d)) return 0; t->rr_bits|=(1ull<<d); return 1;
}

static void handle_wire(transport_t *t, const uint8_t *w, size_t wlen) {
    if (wlen < 8+AB) return;
    uint64_t ctr = ((uint64_t)get32(w)<<32) | get32(w+4);
    uint8_t nonce[NB]; memset(nonce,0,NB); uint64_t be=htobe64(ctr); memcpy(nonce+4,&be,8);
    uint8_t pt[TR_MAXMSG+16]; unsigned long long mlen=0;
    const uint8_t *ct=w+8; size_t clen=wlen-8;
    if (clen < AB+1 || clen-AB > TR_MAXMSG) return;   /* reject oversized: pt is TR_MAXMSG */
    /* try reliable key then unreliable key (channels use different subkeys) */
    int ok = crypto_aead_chacha20poly1305_ietf_decrypt(pt,&mlen,NULL,ct,clen,NULL,0,nonce,t->rx_rel)==0;
    const uint8_t *rk = t->rx_rel;
    if (!ok){ ok = crypto_aead_chacha20poly1305_ietf_decrypt(pt,&mlen,NULL,ct,clen,NULL,0,nonce,t->rx_unrel)==0; rk=t->rx_unrel; }
    if (!ok || mlen<1) return;
    if (!replay_ok(t,ctr)) return;
    (void)rk;
    switch (pt[0]) {
        case CH_REL_DATA: if(mlen>=5) on_rel_data(t, get32(pt+1), pt+5, mlen-5); break;
        case CH_REL_ACK:  if(mlen>=9) on_ack(t, get32(pt+1), get32(pt+5)); break;
        case CH_UNREL:    if(mlen>=5 && t->on_unrel) t->on_unrel(t->user_unrel, pt+5, mlen-5); break;
    }
}

void transport_poll(transport_t *t, int timeout_ms) {
    long now=now_ms();
    for (int i=0;i<TR_WIN;i++) if(t->out[i].used && now-t->out[i].sent>=RTO_MS){
        struct out_msg *m=&t->out[i]; uint8_t p[1+4+TR_MAXMSG]; p[0]=CH_REL_DATA; put32(p+1,m->rseq);
        memcpy(p+5,m->data,m->len); send_pkt(t,t->tx_rel,p,5+m->len); m->sent=now; }
    if (t->relayed) return;
    struct pollfd pf={.fd=t->fd,.events=POLLIN};
    if (poll(&pf,1,timeout_ms)>0 && (pf.revents&POLLIN)){
        uint8_t w[8+TR_MAXMSG+16+8]; ssize_t n;
        while ((n=recv(t->fd,w,sizeof w,MSG_DONTWAIT))>0) handle_wire(t,w,(size_t)n);
    }
}

void transport_set_callbacks(transport_t *t, tr_recv_cb rel, tr_recv_cb unrel, void *user) {
    t->on_rel = rel; t->on_unrel = unrel; t->user = user; t->user_unrel = user;
}

void transport_set_unreliable_cb(transport_t *t, tr_recv_cb unrel, void *user) {
    t->on_unrel = unrel; t->user_unrel = user;
}

void transport_set_relay(transport_t *t, tr_send_fn fn, void *user) {
    t->send_fn = fn; t->send_user = user; t->relayed = 1;
}
void transport_inject(transport_t *t, const uint8_t *wire, size_t len) {
    handle_wire(t, wire, len);
}
