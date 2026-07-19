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
the wrong mapping. (If the first punch attempt fails, later attempts rebind to a
fresh ephemeral port; see §3.6b.)

### 3.3 Gather candidates
- **Host candidates**: every non-loopback local address (IPv4, and global IPv6
  if present), each with the bound port.
- **Server-reflexive (srflx) candidate**: send a STUN Binding Request to a
  public STUN server (the configured list is tried in order until one answers);
  the reply's `XOR-MAPPED-ADDRESS` is your public `ip:port`
  as seen from outside — i.e. the mapping your NAT created for this socket. Two
  srflx candidates are gathered where possible:
  - **IPv4 srflx** — the STUN request goes to the server over IPv4 (reached as a
    v4-mapped address on the dual-stack socket), learning the public IPv4
    `ip:port`.
  - **IPv6 srflx** — a second STUN request goes to the server over *real* IPv6,
    learning the exact global v6 `ip:port` the kernel sources from toward the
    internet. This is only attempted on a dual-stack socket, and quietly skipped
    if the host has no IPv6 path or the STUN server has no AAAA record. See §3.7
    for why the v6 srflx matters even though IPv6 has no NAT.

### 3.4 NAT type detection
Two STUN probes to *different* servers from the same socket. If both report the
**same** public mapping → endpoint-independent (**cone**, punchable). If they
**differ** → **symmetric** (punch may fail). This is printed at startup.

The two probes go to the first two servers that answer from the configured list
(`STUN_SERVERS`; see README), whose default deliberately spans operators — two
probes to one provider share that provider's outage and its blocking. If fewer
than two servers answer, the type is reported `unknown`; the srflx candidate is
still gathered from whatever did answer, so only the diagnostic is lost.

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

### 3.6b Retry with fresh candidates
One punch window is easy to miss: relay latency staggers when each side finishes
the exchange and starts punching, or the very first PINGs hit a NAT mapping that
hasn't warmed yet. So a failed attempt is not the end — telegloomy punches up to
a few times (5 by default, override with `PUNCH_RETRIES`). Before each retry it
re-runs STUN and re-exchanges candidates over the relay, which does two things at
once:

- **Refreshes the reflexive port.** A fixed-port mapping can drift, or may only
  just have opened, since the first STUN probe — so the port the peer was told to
  aim at could already be wrong. Re-STUNning (both the IPv4 and, where present,
  the IPv6 srflx) gets the current one.
- **Re-aligns the two sides.** The re-exchange doubles as a barrier that both
  peers pass through together, so their next punch windows overlap again instead
  of drifting further apart.

- **Re-rolls the local mapping.** From attempt 2 on, the socket is also closed
  and rebound to a fresh **ephemeral** port (bind port 0) before punching. On
  carrier-CGNAT and commercial-VPN paths the external port a socket is granted
  is endpoint-dependent luck that re-STUNning cannot change — the retries reuse
  the same socket, so a run that drew an unpunchable mapping stays unpunchable
  for all of its attempts. That is precisely why quitting and relaunching the
  process by hand connects when an in-process retry loop won't: a new socket
  draws a mapping the peer has never seen. Rebinding does that without a human
  in the loop. Reusing 58712 would risk being handed back the same CGNAT/VPN
  mapping, which is why a fresh ephemeral port is deliberate. Disable with
  `PUNCH_REBIND=0`.

  **This is why the fixed port (§3.2, §5) only covers attempt 1.** That is an
  acceptable trade: the stateful-firewall behaviour in §5 is what carries the
  punch in the common case, and rebinding only ever happens once the fixed port
  has already failed — so easy NATs that punch on attempt 1 keep the benefit of
  the single firewall rule, and hard ones get a fresh roll instead of four more
  attempts at a mapping already known not to work.

Each retry is therefore about as fresh as quitting and starting the whole session
by hand — which is often exactly what makes a stubborn pair finally connect. The
barrier uses a short timeout: if one side has already confirmed and moved on to
the transfer, it is no longer answering, so the other simply times out after a
few seconds and punches once more, confirming on the peer's keepalive PINGs. Each
round's messages are tagged with the attempt number, so a leftover message from
an earlier round is never mistaken for this round's answer; if the two sides ever
drift onto different attempt numbers the tags just miss, the barrier times out,
and each punches anyway — degrading to the old single-shot behaviour rather than
deadlocking.

### 3.7 IPv6 / dual-stack
The socket is `AF_INET6` with `IPV6_V6ONLY=0`, so it handles both IPv6 and
IPv4 (the latter as `::ffff:a.b.c.d`). If a peer has a **global IPv6** address,
there is (usually) no NAT to traverse — but that does *not* mean an IPv6 path
just works, and the naive "advertise every host address" approach quietly fails
in the common case:

- A modern host has **many** global IPv6 addresses on one interface — a stable
  SLAAC address plus a rotating set of RFC 4941 *privacy* addresses. The kernel
  picks the source address for an outbound flow by its own rules, and it is
  usually a *privacy* address, not the one you'd guess.
- If each side just advertises its host v6 addresses, the peer ends up aiming
  PINGs at an address the other side never actually **sends from**. A stateful
  host firewall (see §5) then drops every inbound PING, because it belongs to no
  flow this host originated — so the punch fails even though both peers have
  perfectly good IPv6 connectivity.

The fix is the **IPv6 server-reflexive candidate** (§3.3): a STUN Binding
Request over real IPv6 tells us the *exact* global v6 `ip:port` the kernel
sources from toward the public internet. Advertising that — and, because it's the
socket's own mapping, sending punch PINGs from it — makes both peers open their
firewall pinhole for, and target, the *same* address. The v6 punch then lines up
and confirms, typically almost instantly (no NAT round trip). Without the v6
srflx, IPv6 only worked reliably on the same LAN or between hosts with a single,
predictable global address.

Falls back to IPv4-only if the host has IPv6 disabled (the v6 srflx probe is
skipped). The startup line reports the socket type, and `direct path established
(IPv4|IPv6)` reports which family actually won.

### 3.8 Relay fallback
If no candidate confirms across every attempt (each punch window is ~10 s; see
3.6b), telegloomy gives up on a direct path — typically **symmetric × symmetric**,
or a firewall blocking the UDP — and falls back to relaying the *already
encrypted* transport packets over Nostr (tagged, base64 inside events). Chat
works; file transfer is slow; voice is disabled on this path. This is a graceful
degradation, not a real TURN relay — a public data-relay server would be needed
for low-latency relayed media.

---

## 4. Why symmetric × symmetric fails

If *both* peers are behind symmetric NATs, neither can predict the port the
other's NAT will assign for *this specific* flow, so the exchanged srflx
candidates are already stale by the time the punch happens. The re-STUN on each
retry (3.6b) recovers a mapping that merely *drifted*, but it cannot help here:
a symmetric NAT hands out a fresh, unpredictable port for the peer's flow no
matter how recently we measured our own. Only one side being symmetric is fine
(it punches toward the cone side's stable mapping). The real fixes for the
double-symmetric case are birthday-paradox port prediction (low success) or a
relay — telegloomy uses the Nostr fallback.

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

Note that this rule covers the **first** punch attempt only: retries rebind to a
fresh ephemeral port (§3.6b), which no static rule can name in advance. Those
attempts rely entirely on the stateful `RELATED,ESTABLISHED` accept described
above — which is the mechanism that does the work in the common case anyway. If
you are behind a genuinely stateless firewall and need every attempt to land on
the port you opened, set `PUNCH_REBIND=0`.

---

## 6. Summary of the flow

    bind fixed-port dual-stack socket
        │
        ├─ gather host candidates (IPv4 + global IPv6)
        ├─ STUN over IPv4 ──▶ IPv4 srflx candidate + NAT type
        ├─ STUN over IPv6 ──▶ IPv6 srflx candidate (dual-stack only; skipped if no v6)
        │
    seal + exchange candidates over Nostr (PAKE key)
        │
    ┌─▶ simultaneous STUN-shaped, MAC-authenticated PING/PONG to all candidates
    │       │   (confirm on the peer's ACTUAL source address, not the advertised one)
    │       │
    │       ├─ a path confirms ──▶ connect() ──▶ keepalive ──▶ direct encrypted transport
    │       └─ ~10s window, no confirm
    │             │
    └── rebind to a fresh ephemeral port + re-STUN + re-exchange candidates
        ◀── retry (up to PUNCH_RETRIES)
                  │
                  └─ all attempts fail ──▶ relay-over-Nostr fallback (chat/file, no voice)
