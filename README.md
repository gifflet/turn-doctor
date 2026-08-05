# TURN Doctor

A single-page, client-side tool to diagnose **why a client cannot use a WebRTC TURN relay** — and translate the result into plain guidance.

It forces `iceTransportPolicy: relay` on a **per-transport** basis, so every result isolates exactly one path end to end:

### Reachability

- **STUN reachability & NAT** — finds your public mapping and estimates the NAT type (endpoint‑independent "cone" vs address‑dependent "symmetric").
- **TURN over UDP** — `turn:host:3478?transport=udp`
- **TURN over TCP** — `turn:host:3478?transport=tcp`
- **TURN over TLS** — `turns:host:5349?transport=tcp`

### Relay data path

All of these stand up **two peers in the browser, both forced to relay**, and push real bytes through. They need a credential (there is no allocation without auth) and at least one transport enabled.

- **Relay data flow** — echoes a `DataChannel` through the relay, **once per transport**. Passing proves the relay actually **carries media**, not just that an allocation address was handed out.
- **Packet loss & jitter** — 40 packets over an **unreliable, unordered** channel (`maxRetransmits: 0`), reporting loss %, RTT min/avg/max and RFC 3550 jitter.
- **Payload size (MTU)** — walks 100 → 4000 B looking for the size at which the relay stops forwarding.
- **Soak — sustained flow** — holds the relay open for N seconds, sampling `getStats()` every second and drawing a per-second timeline.
- **Lifetime & silence gaps** — goes deliberately silent for configurable intervals to find where an idle path breaks.

### Why the data-path probes matter

The reachability probes finish as soon as a `relay` candidate appears — but that candidate is minted from the `Allocate` reply on the **control port**, *before* any byte crosses the relay port range. A server can therefore answer allocations perfectly while media never flows (a closed relay port range, or a peer denied by ACL). Reachability alone reports a misleading "pass".

Three specific blind spots the data-path probes exist to close:

**One transport at a time.** Handing all three TURN URLs to a single connection does *not* test all three. libwebrtc's type preference orders relay UDP > TCP > TLS, so the nominated pair is essentially always UDP — a server with healthy UDP but a broken TCP or TLS data path reports a clean pass. That is a false negative on exactly the two transports restrictive corporate clients depend on. Each transport is therefore probed on its own, and the result table shows the `relayProtocol` actually used so you can verify the isolation held.

**Unreliable by design.** A default `DataChannel` is reliable and ordered, so SCTP retransmits whatever the network drops. A multi-second loss window is invisible there, while production RTP — which has no such safety net — glitches. The loss, MTU, soak and gap probes all run over an unreliable channel so drops stay drops.

**Long enough to catch it.** A sub-second echo has almost no chance of landing inside an intermittent bad window. The soak probe holds the path open for minutes and timestamps every second, so red bars can be lined up against the coturn logs.

Each of these probes primes the relay with a few round trips before measuring. A freshly opened relay is an order of magnitude slower for the first packets (SCTP slow start plus permission setup — measured ~300 ms settling to ~13 ms), and counting that startup cost would report a healthy relay as degraded.

From the combination it renders a **verdict**, e.g.:

| Result | Meaning |
| --- | --- |
| Data flow passes on every transport | Relay **verified end to end** — allocation, permissions and the relay port path all work. |
| Data flow passes on some transports | Relay works, but clients limited to a failing transport cannot use it. If **TLS** is among them, corporate/DPI networks fail while a combined test would have looked healthy. |
| Data flow fails, relay allocated | Relay **allocates but carries no data** — relay port range not open, or peer denied by ACL. This is the `rp=0/rb=0` signature in the coturn session logs. |
| Flow passes, quality probes fail | Relay **allocates and then degrades** — what users experience as intermittent drops while reachability checks stay green. |
| Payload cliff below ~1200 B | Small control packets pass, RTP-sized ones do not. Classic with NAT 1:1 + edge DNAT, where the effective MTU shrinks and PMTUD breaks. |
| Silence breaks it at 30–120 s | **Firewall/conntrack** idle timeout on the path — far short of any TURN lifetime. |
| Silence breaks it at ~300 s | TURN **permission** expiring un-refreshed (RFC 8656: 5 min). |
| Silence breaks it at ~600 s | TURN **allocation / channel binding** lifetime (RFC 8656: 10 min). |
| UDP passes | Relay is healthy; intermittency is ICE **selection**, not reachability. Force relay if needed. |
| UDP fails, TCP passes | Network **filters UDP** — advertise `?transport=tcp`. |
| Only TLS passes | Likely **DPI**; serve TURNS on 443 and advertise `turns:`. |
| All fail, 401/403 | **Credential** rejected — path is fine, fix auth. |
| All fail, 701/timeout | Server unreachable / wrong host‑port / relay range closed. |

Everything runs in the browser. **Credentials never leave the page** and are not sent anywhere except to the TURN server you are testing (as a normal ICE allocation).

## Authentication

TURN credentials cannot be derived from the URL alone, so you pick one of two modes:

1. **Shared secret** (coturn `use-auth-secret`) — paste the `static-auth-secret` and a TTL; the page derives ephemeral REST credentials in‑browser:
   `username = expiry[:suffix]`, `password = base64(HMAC-SHA1(secret, username))`.
2. **Direct credential** — a plain `username` / `password` (long‑term credential).

## Run locally

It is a static site (no build). Serve it from `localhost` so WebRTC and Web Crypto run in a secure context:

```bash
cd turn-doctor
python3 -m http.server 8099
# open http://localhost:8099
```

## Deploy to GitHub Pages

1. Push this repo to GitHub.
2. **Settings → Pages → Build and deployment → Source: Deploy from a branch**.
3. Branch: `main`, folder: `/ (root)`. Save.
4. The site publishes at `https://<user>.github.io/turn-doctor/`.

(`.nojekyll` is included so Pages serves the files as‑is.)

## Notes & limitations

- NAT typing is best‑effort (compares your public mapping across two STUN servers); it is a heuristic, not a full RFC 5780 classification.
- Browsers may hide `host` candidate addresses behind mDNS (`.local`) for privacy — that is expected and does not affect TURN results.
- The reachability probes prove **allocation** (control path) only; the data-path probes are what confirm the relay carries bytes.
- The data-path probes connect **two relays on the same server**, so each peer is the server's own external address. Consequences to keep in mind:
  - They confirm auth, allocation, permissions, channel-bind and that the server routes relay↔relay — a strong signal.
  - When the server's external and listening addresses differ (1:1 NAT), that relay↔relay traffic hairpins through the firewall and **does** exercise the relay port range. When they are the same host/loopback, routing may stay internal, so a `pass` does not by itself guarantee an *external* peer can reach the port range. A `fail` (relay allocated, no data) is a strong problem signal; a `pass` is best confirmed against a real external peer for the port-range question.

### What a browser cannot do

Being explicit about the ceiling, so results are not over-read:

- **The TURN protocol itself is invisible.** The browser decides internally between `CreatePermission` and `ChannelBind` and exposes neither the choice nor the `Allocate`/`Refresh` response codes. Only ICE-level outcomes and `getStats()` are reachable from JS. Seeing inside needs coturn verbose logs or `tcpdump` on the server.
- **TLS interception cannot be detected.** There is no access to the certificate chain of a TURNS connection. A corporate proxy that re-signs with a CA trusted by the managed device completes the handshake normally — "TLS passed" does **not** prove the absence of MITM. Confirming that needs `openssl s_client -connect host:443 -showcerts` from inside the affected network, comparing the issuer against the real certificate.
- **The MTU probe is a hint, not a measurement.** A `DataChannel` runs over SCTP, which does its own fragmentation and reassembly, so a lower-layer UDP fragmentation problem can be partly masked. No raw socket, no DF bit. A definitive answer needs `ping -M do -s <size>` from a host on the segment.
- **Silence is never total.** ICE consent freshness (RFC 8445 §11) keeps probing the selected pair every few seconds, so the gap probe bounds an idle-timeout theory rather than proving it.
- **An intermittent fault on a specific network segment will not reproduce here.** Every probe runs from wherever the browser is, over a hairpin relay↔relay path — it never crosses the segment where an internal incident actually happens, unless the page is opened on a device sitting in that segment. Chasing that class of problem properly needs a headless agent (Go with Pion, say) running continuously on a host in the affected segment, logging results that can be correlated with the server logs by timestamp. This tool answers "can this client use this relay, right now, and how well" — not "what broke at 3am on the internal link".
