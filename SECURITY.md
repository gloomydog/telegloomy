# telegloomy — Security design

telegloomy is a serverless P2P tool for chat, file transfer, and voice. Nostr
relays are used only to introduce two peers; once a direct path is established,
all real traffic is end-to-end encrypted and flows peer-to-peer. This document
describes the cryptography, the key schedule, the hardening that has been done,
and an honest threat model.

Everything crypto-related is built on **libsodium**. No cryptographic
primitives are hand-rolled.

---

## 1. Cryptographic primitives

| Purpose                         | Primitive                                   |
|---------------------------------|---------------------------------------------|
| Mutual authentication + key     | **CPace** PAKE over ristretto255 (RFC 9382) |
| Master → channel keys           | **crypto_kdf** (BLAKE2b) key derivation     |
| Data packets (chat/file/voice)  | **ChaCha20-Poly1305 IETF** AEAD             |
| Candidate exchange sealing      | **XChaCha20-Poly1305** AEAD                 |
| Hole-punch PING/PONG auth       | **crypto_auth** (HMAC-SHA-512-256)          |
| File integrity                  | **BLAKE2b** (crypto_generichash)            |
| Passphrase / rendezvous stretch | **Argon2id** (crypto_pwhash)                |
| Relay transport                 | **TLS 1.2+** (wss\://) with cert + hostname |

---

## 2. Pairing and key establishment

### 2.1 Pairing code

The `create` side **generates** a random 12-character pairing code
(~70 bits of entropy, ambiguous glyphs `0/O/1/I/l` removed). The user cannot
pick a weak code by accident. The code is shared out of band (spoken, messaged
over another secure channel, etc.) and typed on the `join` side.

### 2.2 Rendezvous

Both peers derive the same public Nostr tag from the code:

    tag = hex( Argon2id( code, salt = BLAKE2b("telegloomy-nostr-salt-v1:" || code) )[0..16] )

Argon2id (MODERATE: ~256 MB, ~0.5 s, run once) means the **public** tag cannot
be brute-forced back to the code with a cheap offline dictionary attack — the
single most important hardening over a naive `hash(code)` tag. Both peers use
identical parameters, so the derived tag matches deterministically.

### 2.3 CPace handshake

Over the rendezvous tag, the peers run CPace (a balanced PAKE):

1. Each publishes its CPace public point.
2. Each computes the shared session key and a confirmation MAC.
3. Each verifies the peer's confirmation MAC.

Result: a 32-byte master key **K** and *mutual authentication*. A party that
does not know the code cannot compute a matching confirmation MAC, so an active
man-in-the-middle is detected and the handshake aborts. CPace also gives
**forward secrecy** — a later disclosure of the code does not decrypt past
sessions, because the ephemeral CPace scalars are gone.

telegloomy stops after the confirmation step; it does **not** use pakechat's
chat-crypto layer. K becomes the root of its own key schedule.

---

## 3. Key schedule

From K, four (plus two) subkeys are derived with `crypto_kdf` (context
`tglmkdf`), so no single key is reused across roles or directions:

    SUBKEY_SIGNAL      seal the candidate exchange sent over Nostr
    SUBKEY_PUNCH       authenticate hole-punch PING/PONG
    SUBKEY_REL_A2B     reliable stream, initiator → responder
    SUBKEY_REL_B2A     reliable stream, responder → initiator
    SUBKEY_UNREL_A2B   datagrams (voice), initiator → responder
    SUBKEY_UNREL_B2A   datagrams (voice), responder → initiator

Direction separation means a captured packet can never be reflected back in the
opposite direction, and reliable/unreliable channels never share key material.

---

## 4. Data-channel encryption

Every packet on the direct path is individually AEAD-sealed
(ChaCha20-Poly1305 IETF). Wire format:

    [ pktctr : 8 bytes ][ ciphertext ][ Poly1305 tag : 16 bytes ]

- **Nonce**: the 12-byte AEAD nonce is `0x00000000 || pktctr`, where `pktctr`
  is a per-direction 64-bit counter. Because each direction also has its own
  key, **nonces never repeat**. The send counter is mutex-guarded so the voice
  thread and the main thread cannot race and produce a duplicate nonce.
- **Integrity**: the Poly1305 tag authenticates the ciphertext; a flipped
  `pktctr` changes the nonce and fails the tag, so headers are implicitly
  protected too.
- **Anti-replay**: the receiver keeps a 64-packet sliding window over `pktctr`
  and rejects duplicates and too-old packets.
- **Length safety**: the receiver rejects any packet whose plaintext would
  exceed the frame buffer *before* decrypting (this closed a remotely
  triggerable stack overflow found by fuzzing — see §8).

Application framing lives *inside* the AEAD envelope: a 1-byte channel tag
(chat / file-offer / file-chunk / bye) followed by the payload. File chunks,
file names, and offsets are therefore all encrypted.

The reliable channel adds a selective-repeat ARQ (sequence numbers, cumulative
ACK + 32-bit SACK bitmap, retransmit) on top of the authenticated packets;
voice datagrams are fire-and-forget with per-frame Opus and a jitter buffer.

---

## 5. Candidate exchange and hole-punch auth

- **Candidates** (your host and STUN-reflexive IP:port) are serialized and
  sealed with `SUBKEY_SIGNAL` (XChaCha20-Poly1305, random 24-byte nonce) before
  being sent through the relay. A relay sees only ciphertext.
- **Hole-punch** PING/PONG packets carry a random challenge and a `crypto_auth`
  tag keyed by `SUBKEY_PUNCH`. Unauthenticated packets (scanners, spoofers) fail
  verification and are dropped without a reply, so a stray packet cannot forge a
  connection or even learn that something is listening.

---

## 6. Signaling transport

Relay connections are `wss://` (TLS). Certificate verification and hostname
verification are enabled, so a relay cannot be transparently impersonated. The
relay still sees metadata (the tag, timing, volume, the ephemeral pubkey) but
never plaintext. Nostr identities are freshly generated per session.

---

## 7. Memory hygiene

K, the subkey material, and the punch key are wiped with `sodium_memzero`
after the session keys are set up; the transport and signaling structs are
zeroed on teardown.

---

## 8. Hardening and testing

Reproducible from the repo:

- **`make fuzz`** — a mutation fuzzer drives every attacker-facing parser
  (WebSocket frame, Nostr event, envelope, candidate, transport packet) under
  **AddressSanitizer + UBSan**. This found and fixed a **remotely triggerable
  stack buffer overflow** in the transport decrypt path (an oversized relayed
  packet could overflow a fixed plaintext buffer). ~2.5M iterations clean after
  the fix.
- **`make asan`** — the unit tests under AddressSanitizer + UBSan.
- **`make tsan`** — the concurrent send path and voice jitter buffer under
  **ThreadSanitizer**. This found and fixed a real **data race** (the unreliable
  send path read the reliable sequence counter across threads). Cross-thread
  flags were converted to C11 atomics.
- A teardown **use-after-free** (a relay reader thread touching freed SSL when
  signaling closed after a successful punch) was fixed by interrupting and
  joining reader threads before freeing, and the resulting write-to-closed-socket
  was handled with `SHUT_RD` + ignoring `SIGPIPE`.

---

## 9. Threat model

**Assets**: confidentiality + integrity of content; authentication of the peer;
minimising metadata.

| Adversary                              | Can they…                                                                 |
|----------------------------------------|---------------------------------------------------------------------------|
| Passive network / relay eavesdropper   | Read content? **No.** Recover code from the tag offline? **No** (Argon2id).|
| Active MITM without the code           | Complete CPace / inject accepted packets? **No.**                          |
| Malicious relay                        | Read/forge? **No.** Drop, delay, reorder, observe metadata? **Yes.**       |
| Malformed / oversized-input attacker   | Crash the parsers? **Not in fuzzing**; decrypt path is length-bounded.     |
| Malicious peer who holds the code      | Trusted by assumption (inside the boundary); receive paths still bounds-checked. |

---

## 10. Known limitations (out of scope)
- A relay sees metadata (tag, timing, volume, ephemeral pubkey).
- After a direct connection, your public IP is visible to the peer and to the
  STUN server. Run over a VPN/WireGuard interface if you need to hide it.
- The relay-fallback datapath (used when hole punching fails, e.g. symmetric ×
  symmetric NAT) carries the already-encrypted stream, but is high-latency and
  rate-limited: fine for chat, slow for files, **voice disabled** on that path.
  A real TURN/data-relay server would be the fix.
- Endpoint compromise, the code leaking out of band, denial of service, and
  global-passive traffic analysis are all out of scope.
- This is a personal project, not a substitute for a professionally audited
  messenger.
