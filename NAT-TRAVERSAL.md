# telegloomy — NAT traversal

How two peers behind home routers establish a *direct* UDP path with no server
in the middle, using a Nostr relay only to introduce themselves.

---

## 1. The problem

Most machines are behind a NAT (Network Address Translation) router. They have a
private address (`192.168.x.y`) and share one public address. A NAT only lets in
traffic that is a reply to something that went out — an unsolicited packet from
the internet is dropped. So two peers, both behind NATs, cannot simply send each
other packets: neither router will let the first packet in.

NAT behaviour comes in two families that matter here:

- **Cone** (typical home routers): once you send *out* from a socket, the router
  creates a mapping `(internal ip:port) ↔ (public ip:port)` and **reuses it
  regardless of destination**. So a public address learned once (via STUN) is
  valid for any peer that sends to it. → punchable.
- **Symmetric** (corporate / carrier-grade NAT): the mapping is **different per
  destination**. The public address you learned by talking to a STUN server is
  *not* the address a peer must send to. → hard to punch.

---

## 2. The pieces

    ┌─────────────┐        Nostr relays (wss)         ┌─────────────┐
    │   Peer A    │ ───── rendezvous + PAKE + ──────  │   Peer B    │
    │  (create)   │       sealed candidate exchange   │   (join)    │
    └─────┬───────┘                                   └──────┬──────┘
          │                                                  │
          │            direct UDP after hole punch           │
          └──────────────────────────────────────────────────┘

Signaling (introductions) goes over Nostr relays. The actual media path is a
single UDP socket punched directly between the peers. STUN is used only to learn
each peer's public address.

---

## 3. Step by step

### 3.1 Rendezvous + shared key
Both peers derive the same Nostr tag from the pairing code (Argon2id) and run
the CPace PAKE over it, yielding a shared key **K** and mutual authentication.
(See SECURITY.md.) K is used to seal the candidate exchange and to key the
eventual direct channel.

### 3.2 Bind one socket
A single dual-stack UDP socket is bound to a **fixed port** (default 58712).
The same socket is used for STUN, hole punching, and data — this matters,
because a NAT mapping is per-socket: STUNning from a different socket would learn
the wrong mapping.

### 3.3 Gather candidates
- **Host candidates**: every non-loopback local address (IPv4, and global IPv6
  if present), each with the bound port.
- **Server-reflexive (srflx) candidate**: send a STUN Binding Request to a
  public STUN server; the reply's `XOR-MAPPED-ADDRESS` is your public `ip:port`
  as seen from outside — i.e. the mapping your NAT created for this socket.

### 3.4 NAT type detection
Two STUN probes to *different* servers from the same socket. If both report the
**same** public mapping → endpoint-independent (**cone**, punchable). If they
**differ** → **symmetric** (punch may fail). This is printed at startup.

### 3.5 Exchange candidates
The candidate list is serialized, sealed with a K-derived subkey, and sent
through the relay. The peer's list arrives the same way and is decrypted. Now
each side knows all of the other's `ip:port` guesses.

### 3.6 Simultaneous hole punch
Both peers, at the same time, send small authenticated **PING** packets to *all*
of the peer's candidates, repeating every ~60 ms:

    A ──PING──▶ (B's candidates)        B ──PING──▶ (A's candidates)

The first PINGs are usually dropped by the far NAT — but each one **opens the
local mapping** on the way out. Once both sides have sent, both mappings are
open, and subsequent packets get through.

**Packet shape.** PING/PONG are deliberately shaped like STUN Binding
Requests/Responses — the real STUN magic cookie (`0x2112A442`), STUN message
types (`0x0001`/`0x0101`), and an 8-byte challenge tucked into the 12-byte
transaction-id field. Some carrier and mobile networks treat unrecognised small
UDP payloads differently from STUN traffic, and looking like STUN measurably
improves reachability. A real STUN server that receives one just ignores it (the
transaction id matches nothing it issued). Every packet also carries a
`crypto_auth` MAC over its header, keyed by a K-derived subkey, appended after
the STUN header — so the punch is **authenticated**: stray, forged, or injected
packets (and stray real STUN responses) fail the MAC and are dropped. Because K
comes from the PAKE *before* punching, this MAC is a genuine secret, not a
world-readable token.

**Confirmation is on the *actual source*, never the advertised candidate.** When
a peer receives a valid PING it replies with a **PONG** echoing the challenge,
and takes the address the PING *actually arrived from* as the path — a peer's
NAT may map a different port toward us than the one it advertised (common on
carrier NAT), and that arrival address is the only one that works. Receiving
either an authenticated PING or a PONG that echoes our own fresh challenge
confirms the path; the socket is `connect()`ed to that source and punching
stops. (The fresh challenge on the PONG route also stops a captured PONG being
replayed.)

Because *all* candidates are raced in parallel, the fastest working path wins
naturally — e.g. a direct IPv6 or same-LAN host path confirms almost instantly,
while an srflx path takes a round trip through the public internet.

### 3.6a Keepalive
Once the path is `connect()`ed, a background thread keeps sending punch PINGs to
the peer every ~15 s. This holds the NAT mapping and stateful-firewall entry
open — Linux conntrack expires idle UDP after 30 s (unconfirmed) to 120 s, and
carrier NATs are far more aggressive, so an idle chat with no keepalive would
silently lose its mapping. The keepalive doubles as continued punching: a peer
that has not confirmed yet will confirm on the next keepalive PING it receives.
Inbound keepalives arrive on the same socket and are dropped by the transport
(they fail its AEAD), so they never reach the application.

### 3.7 IPv6 / dual-stack
The socket is `AF_INET6` with `IPV6_V6ONLY=0`, so it handles both IPv6 and
IPv4 (the latter as `::ffff:a.b.c.d`). If a peer has a **global IPv6** address,
there is no NAT to traverse: the IPv6 host candidate is reached directly, STUN
and NAT concerns simply don't apply, and that path usually wins. Falls back to
IPv4-only if the host has IPv6 disabled. The startup line reports the socket
type, and `direct path established (IPv4|IPv6)` reports which family actually
won.

### 3.8 Relay fallback
If no candidate confirms within ~10 s (typically **symmetric × symmetric**, or a
firewall blocking the UDP), telegloomy falls back to relaying the *already
encrypted* transport packets over Nostr (tagged, base64 inside events). Chat
works; file transfer is slow; voice is disabled on this path. This is a
graceful degradation, not a real TURN relay — a public data-relay server would
be needed for low-latency relayed media.

---

## 4. Why symmetric × symmetric fails

If *both* peers are behind symmetric NATs, neither can predict the port the
other's NAT will assign for *this specific* flow, so the exchanged srflx
candidates are already stale by the time the punch happens. Only one side being
symmetric is fine (it punches toward the cone side's stable mapping). Fixes for
the double-symmetric case are birthday-paradox port prediction (low success) or
a relay (telegloomy uses the Nostr fallback).

---

## 5. Firewalls are a separate wall — but a stateful one

NAT is only the first gate. Even after a packet clears the router, the **host
firewall** decides whether to hand it to the app. The good news: most host
firewalls (`ufw`, `firewalld`, Windows Defender) are *stateful*. `ufw`'s default
"deny incoming" ruleset still contains an early conntrack `RELATED,ESTABLISHED`
accept, so any UDP packet belonging to a flow this host already sent out is let
through.

Hole punching exploits exactly this. It's a simultaneous open: both peers fire
outbound PINGs first, which create conntrack state on their own firewall. The
peer's PING then arrives as part of an "established" UDP flow and is accepted —
**even with `ufw` on and no explicit rule for the port**. In practice you rarely
need to touch the host firewall at all.

An explicit rule only matters at the edges: a stricter/stateless firewall, or the
UDP conntrack entry expiring (it has a short idle timeout) before both sides have
exchanged a packet. Because telegloomy binds a **fixed** UDP port, adding that
belt-and-suspenders rule is a single line:

    sudo ufw allow 58712/udp                         # Linux / ufw
    New-NetFirewallRule -DisplayName "telegloomy" \  # Windows (PowerShell, admin)
      -Direction Inbound -Protocol UDP -LocalPort 58712 -Action Allow

Override the port with `P2P_PORT=<port>` if 58712 is taken.

---

## 6. Summary of the flow

    bind fixed-port dual-stack socket
        │
        ├─ gather host candidates
        ├─ STUN  ──▶ srflx candidate + NAT type
        │
    seal + exchange candidates over Nostr (PAKE key)
        │
    simultaneous STUN-shaped, MAC-authenticated PING/PONG to all candidates
        │   (confirm on the peer's ACTUAL source address, not the advertised one)
        │
        ├─ a path confirms ──▶ connect() ──▶ keepalive ──▶ direct encrypted transport
        └─ 10s timeout      ──▶ relay-over-Nostr fallback (chat/file, no voice)
