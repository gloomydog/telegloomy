# telegloomy_cli: E2E encrypted P2P chat  

Serverless, end-to-end encrypted P2P **chat / file transfer / voice** over
NAT. A public Nostr relay is used only to introduce two peers; once a direct
path is punched through, all real traffic flows peer-to-peer and encrypted.
A single pairing code (CPace PAKE) derives every channel key.

**Docs:** [SECURITY.md](SECURITY.md) · [NAT-TRAVERSAL.md](NAT-TRAVERSAL.md) 

[![CI](https://github.com/gloomydog/telegloomy/actions/workflows/ci.yml/badge.svg)](https://github.com/gloomydog/telegloomy/actions/workflows/ci.yml)
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

## Install dependencies
 
**Arch Linux:**
 
    sudo pacman -S base-devel libsodium cjson libsecp256k1 openssl opus pipewire
 
**Ubuntu / Debian:**
 
    sudo apt-get update
    sudo apt-get install -y build-essential pkg-config \
        libsodium-dev libcjson-dev libsecp256k1-dev libssl-dev \
        libopus-dev libpipewire-0.3-dev
 
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

    make                 # unit tests + ./telegloomy (chat + file)
    make test            # build and run all unit tests
    make telegloomy-voice       # ./telegloomy with voice (Opus + PipeWire)

## Firewall
telegloomy binds a FIXED UDP port (default 58712, same for both create and join).
Most host firewalls (ufw, firewalld, Windows Defender) are *stateful*: even with
the default "deny incoming", they still accept the return traffic for a UDP flow
the host already sent out (conntrack `RELATED,ESTABLISHED`). Because hole punching
is a simultaneous open -- both peers fire outbound PINGs first -- the peer's PING
arrives as part of an already-established flow and is let through. **You can leave
ufw on and hole punching still works; you usually don't need to open anything.**

If you want to be robust against edge cases -- a stricter/stateless firewall, or
the short UDP conntrack entry timing out before both sides exchange a packet --
opening the fixed port is a single rule:

    sudo ufw allow 58712/udp     # Linux/ufw; adjust for your firewall

Override the port with `P2P_PORT=<port>` if 58712 is taken (the default was
chosen to avoid the WireGuard-standard 51820, which VPN setups often claim). Both peers can use
different ports -- each just opens its own port on its own firewall.

## Run
    ./telegloomy create <passphrase> [relay_host]     # peer A prints/uses the passphrase
    ./telegloomy join   <passphrase> [relay_host]     # peer B uses the same passphrase
Both peers fan out across several built-in public relays (relay.damus.io,
relay.primal.net, relay.nostr.band, nos.lol) at once, so one relay being down
doesn't block rendezvous; an optional `relay_host` is simply tried first. Then:
type to chat, "/file <path>" to send, "/call" / "/hangup" for voice (voice
build), "/quit".

On connect it prints the NAT type and which relays it reached, then hole-punches.
A punch often just misses on the first try, so it makes a few attempts (3 by
default; set `PUNCH_RETRIES` to change), re-running STUN and re-exchanging
candidates between attempts so each try is as fresh as restarting the session by
hand. If every attempt fails (e.g. symmetric x symmetric NAT) it falls back to
relaying the encrypted stream over Nostr -- chat works, file transfer is slow,
and voice is disabled on that path.

## Key schedule (from PAKE master K = cpace.session_key, 32 bytes)
    SUBKEY_SIGNAL        seal candidate exchange over Nostr
    SUBKEY_PUNCH         authenticate hole-punch PING/PONG
    SUBKEY_REL_{A2B,B2A} reliable stream (chat/file)
    SUBKEY_UNREL_{A2B,B2A} datagrams (voice), nonce = seq

## Roadmap
    m0 STUN                          done (v4 + real-v6 server-reflexive)
    m1 NAT type detection            done (2 STUN probes, cone vs symmetric)
    m2 signaling (rendezvous+CPace)  done (wired onto pakechat_cli)
    m3 UDP hole punch                done
    m4 multiplex framing             done
    m5 chat                          done
    m6 file transfer                 done
    m7 voice                         done (Opus + jitter/PLC + noise gate; PipeWire I/O compile-checked)

## Security

Hardening: `make fuzz` mutation-fuzzes every attacker-facing parser under
ASAN+UBSAN (this found and fixed a remote stack overflow in the transport
decrypt path); `make asan` runs the tests under AddressSanitizer; `make tsan`
checks the threaded send path + jitter buffer with ThreadSanitizer (found and
fixed one send-counter race). Cross-thread flags are C11 atomics. A teardown use-after-free (a relay
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
  a cheap offline dictionary attack. Both peers run identical params, ~0.7 s once.
- K, the per-hop subkeys' source, and the punch key are wiped (sodium_memzero)
  after the session keys are set up.

Honest limitations:
- A relay sees metadata: the rendezvous tag, traffic volume, timing, and the
  ephemeral pubkey -- never plaintext.
- After a successful punch the peer (and the STUN server) sees your public IP.
  Run over a VPN/WireGuard interface if you need to hide it.
- The relay-fallback datapath carries the already-encrypted stream, but it is
  high-latency/rate-limited: fine for chat, slow for files, voice disabled.
- Not a substitute for a professionally audited messenger.

## Known gaps
- multi-relay + PAKE handshake are validated by compile + unit tests; the live
  path (real relays + two real NATs) is not covered by in-repo tests.
- symmetric x symmetric now degrades to a Nostr-relayed datapath instead of
  failing outright, but this is not a real TURN relay: it is high-latency and
  rate-limited, fine for chat, slow for files, unusable for voice. A proper
  TURN/data-relay server would be the real fix.
- IPv6 is supported via a dual-stack socket (IPv6 + IPv4-mapped). Both an IPv4
  server-reflexive candidate (STUN over v4) and an IPv6 one (STUN over real v6)
  are gathered: the v6 srflx is the exact global address the kernel sources from,
  so both peers punch toward/from the *same* v6 address instead of a random
  SLAAC/privacy address the firewall would drop. Local host candidates are also
  raced (same-LAN wins instantly). Falls back to IPv4-only if the host has IPv6
  disabled (v6 srflx probe skipped). The dual-stack + v6-srflx path is
  logic-tested but not run-tested in the (IPv6-disabled) build sandbox.
- voice codec/jitter/PLC is unit-tested; the PipeWire I/O path compiles but is
  not run-tested here (no audio device in the build sandbox).
- handshake resend is best-effort (a few CONFIRM repeats); a real ack would be
  more robust under heavy relay loss.

## License

MIT — see [LICENSE](LICENSE). The vendored CPace/Nostr/WebSocket code under
`third_party/pakechat/` is also MIT (see `third_party/pakechat/LICENSE`).
