# telegloomy: E2E encrypted P2P chat 

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
    src/stun.{h,c}      STUN binding (RFC 5389); stun_query_on(fd); nat_detect (cone/symmetric)
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
    tests/              test_candidate, test_punch, test_transport, test_app

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
telegloomy binds a FIXED UDP port (default 58712, same for both create and join) so a
firewall only needs one rule instead of a different random port every run:

    sudo ufw allow 58712/udp     # Linux/ufw; adjust for your firewall

Override the port with `P2P_PORT=<port>` if 58712 is taken (the default was
chosen to avoid the WireGuard-standard 51820, which VPN setups often claim). Both peers can use
different ports -- each just opens its own port on its own firewall.
Without this, hole punching can fail asymmetrically: if either side's firewall
defaults to "deny incoming" (ufw's default), packets from the peer never reach
the app even though the peer's side looks fine, and you fall back to the
slower/voice-disabled relay path.

## Run
    ./telegloomy create <passphrase> [relay_host]     # peer A prints/uses the passphrase
    ./telegloomy join   <passphrase> [relay_host]     # peer B uses the same passphrase
Default relay: nos.lol. Then: type to chat, "/file <path>" to send, "/call"/"/hangup" for voice (voice build), "/quit".

On connect it prints the NAT type and which relays it reached. If hole
punching fails (e.g. symmetric x symmetric NAT) it automatically falls back to
relaying the encrypted stream over Nostr -- chat works, file is slow, voice is
disabled on that path.

## Key schedule (from PAKE master K = cpace.session_key, 32 bytes)
    SUBKEY_SIGNAL        seal candidate exchange over Nostr
    SUBKEY_PUNCH         authenticate hole-punch PING/PONG
    SUBKEY_REL_{A2B,B2A} reliable stream (chat/file)
    SUBKEY_UNREL_{A2B,B2A} datagrams (voice), nonce = seq

## Roadmap
    m0 STUN                          done
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
PING/PONG is authenticated with keyed BLAKE2b (crypto_auth). Nostr identities are
ephemeral per session; CPace gives mutual authentication (a peer without the code
fails the confirmation MAC) and forward secrecy.

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
- IPv6 is supported via a dual-stack socket (IPv6 + IPv4-mapped); IPv6 host
  candidates are punched directly (no STUN/NAT needed). Falls back to IPv4-only
  if the host has IPv6 disabled. The dual-stack socket path is logic-tested but
  not run-tested in the (IPv6-disabled) build sandbox.
- voice codec/jitter/PLC is unit-tested; the PipeWire I/O path compiles but is
  not run-tested here (no audio device in the build sandbox).
- handshake resend is best-effort (a few CONFIRM repeats); a real ack would be
  more robust under heavy relay loss.

## License

MIT — see [LICENSE](LICENSE). The vendored CPace/Nostr/WebSocket code under
`third_party/pakechat/` is also MIT (see `third_party/pakechat/LICENSE`).
