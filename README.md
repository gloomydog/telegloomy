# telegloomy_cli: E2E encrypted P2P chat  

Serverless, End-to-End encrypted Peer-to-Peer **chat / file transfer / voice** over
NAT working on CLI.

A public Nostr relay is used only to introduce two peers. Once a direct
path is punched through, all real traffic flows peer-to-peer and encrypted.
A single pairing code (CPace PAKE) derives every channel key.

**Docs:** [SECURITY.md](SECURITY.md) · [NAT-TRAVERSAL.md](NAT-TRAVERSAL.md) 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Layout
    src/common.h        ep_t, candidate_t
    src/keys.{h,c}      K -> per-direction subkeys (crypto_kdf)
    src/stun.{h,c}      STUN binding (RFC 5389); stun_query_on/stun_query6_on(fd) (v4 + v6 srflx); nat_detect (cone/symmetric)
    src/net.{h,c}       ep <-> sockaddr (v4-mapped aware), udp_bind / udp_bind_any / udp_bind_dual
    src/candidate.{h,c} gather host+srflx candidates, wire format, AEAD seal/open
    src/punch.{h,c}     authenticated UDP hole punch (PING/PONG + crypto_auth)
    src/transport.{h,c} per-packet AEAD, anti-replay, SR-ARQ + datagrams; pluggable datapath (relay fallback)
    src/app.{h,c}       chat + file over the reliable channel (BLAKE2b verify, backpressure)
    src/signaling.{h,c} Nostr + CPace over MULTIPLE relays (reader threads + queue)
    src/voice.{h,c}     Opus encode/decode + jitter buffer + PLC (unreliable channel)
    src/audio_pipewire.{h,c} PipeWire capture/playback backend driving voice
    third_party/pakechat/    vendored CPace / Nostr / WebSocket (from pakechat_cli)
                             (ws_client.c: local patch adds connect + handshake timeouts)
    src/main.c          end-to-end telegloomy binary
    tests/              test_candidate, test_punch, test_transport, test_app, test_voice
                        test_race (ThreadSanitizer target, see `make tsan`)

## Install dependencies
 
**Arch Linux:**
 
    sudo pacman -S base-devel libsodium cjson libsecp256k1 openssl opus pipewire
 
**Ubuntu / Debian:**
 
    sudo apt-get update
    sudo apt-get install -y build-essential pkg-config \
        libsodium-dev libcjson-dev libsecp256k1-dev libssl-dev \
        libopus-dev libpipewire-0.3-devNonlinear Dynamics And Chaos: With Applications To Physics, Biology, Chemistry, And Engineering 
 
`libsodium-dev`, `libcjson-dev`, `libsecp256k1-dev`, `libssl-dev` are required
for the core build (chat + file transfer). `libopus-dev` and
`libpipewire-0.3-dev` (Ubuntu) / `opus` and `pipewire` (Arch) are only needed
for `make telegloomy-voice` (adds voice calls).
 
If `libsecp256k1-dev` isn't available on your distro/version, build it from
source: https://github.com/bitcoin-core/secp256k1

## Build
Self-contained -- the needed pakechat_cli sources are vendored under
`third_party/pakechat/`(https://github.com/gloomydog/pakechat_cli), so no external path is required.

System deps: libsodium, libcjson, libsecp256k1, openssl (+ opus, pipewire
for the voice build).

    make                 # ./telegloomy (chat + file)
    make test            # build and run all unit tests
    make telegloomy-voice       # ./telegloomy-voice (adds voice: Opus + PipeWire)
    make clean           # remove binaries and objects

`telegloomy-voice` is a separate binary built from the same sources with
`-DWITH_VOICE`is. It does everything `telegloomy` does, plus `/call`.

## Firewall
telegloomy binds a FIXED UDP port (default 58712, same for both create and join).
Most host firewalls (ufw, firewalld, Windows Defender) are *stateful*.It means even with
the default "deny incoming", they still accept the return traffic for a UDP flow
the host already sent out (conntrack `RELATED,ESTABLISHED`). Because hole punching
is a simultaneous open,the peer's PING arrives as part of an already-established flow and is let through. 
**You can leave ufw on and hole punching still works. So,you usually don't need to open any ports.**

If you want to be robust against edge cases (stricter/stateless firewall, or
the short UDP conntrack entry timing out before both sides exchange a packet),
open the fixed port.

    sudo ufw allow 58712/udp     # Linux/ufw

Override the port with `P2P_PORT=<port>` if 58712 is taken. Both peers can use
different ports. Each just opens its own port on its own firewall.

**The fixed port applies to the first punch attempt only.** If that attempt
fails, telegloomy rebinds to a fresh *ephemeral* port before each retry, to
re-roll a NAT mapping that turned out to be unpunchable (see
[NAT-TRAVERSAL.md](NAT-TRAVERSAL.md) §3.6b). So an explicit `allow 58712/udp`
rule only covers attempt 1  which is the case that matters, since the
stateful-firewall behaviour above is what carries the retries. Set
`PUNCH_REBIND=0` to disable rebinding and keep every attempt on the fixed port,
at the cost of losing the re-roll.

## Run
    ./telegloomy create [relay_host]            # peer A: prints a strong pairing code
    ./telegloomy join <code> [relay_host]       # peer B: use the code peer A printed
- `create` generates the pairing code itself (you don't supply one)
- `join` takes that code. Both peers fan out across several built-in public relays (relay.damus.io,
relay.primal.net, relay.nostr.band, nos.lol) at once, so one relay being down
doesn't block rendezvous.
- an optional `relay_host` is simply tried first. 
- type to chat
- "/file <path>" to send
- "/call" / "/hangup" for voice (voice build) 
- "/quit" for stopping a sesssion.

Received files are written to the **current working directory** as
`received_<name>`, after the BLAKE2b hash is verified ( a file that fails the
hash check is discarded, not saved ). The peer-supplied name is reduced to a bare
basename first, so it can never contain a path separator or escape the cwd.

On connect it prints the NAT type and which relays it reached, then hole-punches.
A punch often just misses on the first try, so it makes a few attempts (5 by
default; set `PUNCH_RETRIES` to change). Between attempts it reruns STUN,
re-exchanges candidates, and rebinds to a fresh local port, so each try is as
fresh as restarting the session by hand (`PUNCH_REBIND=0` keeps every attempt on
the fixed port ). If every attempt fails (e.g. symmetric x
symmetric NAT) it falls back to relaying the encrypted stream over Nostr. There, chat
works, file transfer is slow, and voice is disabled on that path.

## What connects with what
Two things decide whether you get a direct path. 
- the peers must share an **address family**
- **NAT types** must allow a punch.

First, address family. Candidates from both families are raced, so a peer only
needs *one* family in common with the other side:

| v4 only | v6 only | dual (v4+v6)|
| --- | --- |--- | 
|v4 only     | ok (v4) | RELAY   | ok (v4)|
|v6 only     | RELAY   | ok (v6) | ok (v6)|
|dual        | ok (v4) | ok (v6) | ok (v6 usually wins the race)|

**A v4-only peer and a v6-only peer share nothing to punch over, so that pair
always relays.** 

Second, NAT type. This applies to the pairs that land on IPv4:

| cone           | symmetric      |
| --- | --- | 
|cone        | direct         | direct         | 
|symmetric   | direct         | RELAY          |


`ok` / `direct` = hole-punched UDP; P2P chat, file transfer and voice all work.
`RELAY` = the encrypted stream is tunnelled over Nostr; chat works, file
transfer is slow, voice is disabled. 
Only two cells are guaranteed relays.**v4-only x v6-only** (no shared family) and **symmetric x symmetric** (no
predictable port). 

Environment variables: `P2P_PORT` (fixed UDP port, default 58712),
`PUNCH_RETRIES` (punch attempts, default 5), `PUNCH_REBIND=0` (disable the
per-retry rebind), `STUN_SERVERS` (see below).

## STUN servers
Servers are tried in order until one answers, so a blocked or dead provider
costs a timeout rather than the whole reflexive candidate. The default list
spans several operators on purpose. A single-operator list fails as one unit:

    stun.l.google.com:19302   stun.cloudflare.com:3478
    stun1.l.google.com:19302  stun.nextcloud.com:443

Override it with `STUN_SERVERS`, a comma- or space-separated list of
`host[:port]` (port defaults to 3478; bracket IPv6 literals to give them one):

    STUN_SERVERS=stun.cloudflare.com:3478,stun.nextcloud.com:443 ./telegloomy create
    STUN_SERVERS="[2001:db8::1]:3478 stun.example.org" ./telegloomy join <code>

An unset, empty, or wholly unparseable value keeps the defaults; at most 8
entries are used. The list in effect is printed at startup.

**Give it at least two reachable servers.** Cone-vs-symmetric detection works by
comparing the mapping two different servers report.


## Key schedule (from PAKE master K = cpace.session_key, 32 bytes)
    SUBKEY_SIGNAL        seal candidate exchange over Nostr
    SUBKEY_PUNCH         authenticate hole-punch PING/PONG
    SUBKEY_REL_{A2B,B2A} reliable stream (chat/file)
    SUBKEY_UNREL_{A2B,B2A} datagrams (voice; per-packet seq carried in payload)
    
## Security

Hardening: `make fuzz` mutation-fuzzes every attacker-facing parser under
ASAN+UBSAN (this found and fixed a remote stack overflow in the transport
decrypt path); `make asan` runs the tests under AddressSanitizer; `make tsan`
checks the threaded send path + jitter buffer with ThreadSanitizer (found and
fixed one send-counter race). The signaling layer's cross-thread flags are C11
atomics; the keepalive thread's stop flag is a `volatile int` that is only ever
read across threads and is joined on shutdown. A teardown use-after-free (a relay
reader thread touching freed SSL when the signaling connection closed after a
successful punch) was fixed by interrupting + joining readers before freeing.
See SECURITY.md for the full crypto design and threat model.


Data path: every chat/file/voice packet is AEAD (ChaCha20-Poly1305 IETF),
authenticated and encrypted. Keys are derived from the CPace shared key K via
crypto_kdf into four direction-separated subkeys (reliable/unreliable x each
direction). The AEAD nonce is a per-direction 64-bit counter and each direction
has its own key, so nonces never repeat (the send counter is mutex-guarded so
the voice thread and main thread can't collide). Replay is blocked by a 64-packet
sliding window. Candidate exchange is sealed with XChaCha20-Poly1305; hole-punch
PING/PONG is authenticated with crypto_auth (HMAC-SHA-512-256). Nostr identities
are ephemeral per session; CPace gives mutual authentication (a peer without the
code fails the confirmation MAC) and forward secrecy.

Passphrase hardening:
- `create` GENERATES a strong 12-char pairing code (~70 bits, ambiguous glyphs
  removed); you can't accidentally pick a weak one.
- The public Nostr rendezvous tag is derived with Argon2id (crypto_pwhash,
  MODERATE), not a fast hash, so it can't be brute-forced back to the code with
  a cheap offline dictionary attack. Both peers run identical params (~256 MB,
  well under a second on a normal machine), once per session.
- K, the per-hop subkeys' source, and the punch key are wiped (sodium_memzero)
  after the session keys are set up.
  
## Known gaps
- A relay sever sees your metadata: the rendezvous tag, traffic volume, timing, and the
  ephemeral pubkey.
- After a successful punch, the peer (and the STUN server) sees your public IP.
  Run over a VPN/WireGuard interface if you need to hide it.
- symmetric x symmetric NAT now degrades to a Nostr-relayed datapath instead of
  failing outright, but this is not a real TURN relay, so it is high-latency and
  rate-limited, fine for chat, slow for files, unusable for voice. 
- IPv6 is supported through a dual-stack socket (IPv6 + IPv4-mapped). The client gathers both an IPv4 server-reflexive candidate (via STUN over v4) and an IPv6 one (via STUN over real v6). The v6 srflx candidate is the exact global address the kernel sources from, so both peers punch to/from the same v6 address, rather than a random SLAAC/privacy address that the firewall would drop. Local host candidates are raced as well, so same-LAN connections win instantly. If the host has IPv6 disabled, the client falls back to IPv4 only (the v6 srflx probe is simply skipped). 


## License

MIT — see [LICENSE](LICENSE). The vendored CPace/Nostr/WebSocket code under
`third_party/pakechat/` is also MIT (see `third_party/pakechat/LICENSE`).
