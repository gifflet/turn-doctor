# TURN Doctor

A single-page, client-side tool to diagnose **why a client cannot use a WebRTC TURN relay** — and translate the result into plain guidance.

It forces `iceTransportPolicy: relay` on a **per-transport** basis, so every result isolates exactly one path end to end:

- **STUN reachability & NAT** — finds your public mapping and estimates the NAT type (endpoint‑independent "cone" vs address‑dependent "symmetric").
- **TURN over UDP** — `turn:host:3478?transport=udp`
- **TURN over TCP** — `turn:host:3478?transport=tcp`
- **TURN over TLS** — `turns:host:5349?transport=tcp`
- **TURN relay data flow** — stands up **two peers in the browser, both forced to relay**, connects them, and echoes a `DataChannel` **through the relay**. Passing proves the relay actually **carries media** — not just that an allocation address was handed out. Needs a credential and runs automatically when one is present.

### Why the data-flow test matters

The per-transport probes finish as soon as a `relay` candidate appears — but that candidate is minted from the `Allocate` reply on the **control port**, *before* any byte crosses the relay port range. A server can therefore answer allocations perfectly while media never flows (a closed relay port range, or a peer denied by ACL). Reachability alone reports a misleading "pass"; the data-flow test pushes real bytes through the relay and catches it.

From the combination it renders a **verdict**, e.g.:

| Result | Meaning |
| --- | --- |
| Data flow passes | Relay **verified end to end** — allocation, permissions and the relay port path all work. |
| Data flow fails, relay allocated | Relay **allocates but carries no data** — relay port range not open, or peer denied by ACL. |
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
- The per-transport probes prove **allocation** (control path) only; the **data-flow test** is what confirms the relay carries bytes.
- The data-flow test connects **two relays on the same server**, so each peer is the server's own external address. Consequences to keep in mind:
  - It confirms auth, allocation, permissions, channel-bind and that the server routes relay↔relay — a strong signal, and it does not measure sustained throughput.
  - When the server's external and listening addresses differ (1:1 NAT), that relay↔relay traffic hairpins through the firewall and **does** exercise the relay port range. When they are the same host/loopback, routing may stay internal, so a `pass` does not by itself guarantee an *external* peer can reach the port range. A `fail` (relay allocated, no data) is a strong problem signal; a `pass` is best confirmed against a real external peer for the port-range question.
