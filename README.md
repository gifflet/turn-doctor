# TURN Doctor

A single-page, client-side tool to diagnose **why a client cannot use a WebRTC TURN relay** — and translate the result into plain guidance.

It forces `iceTransportPolicy: relay` on a **per-transport** basis, so every result isolates exactly one path end to end:

- **STUN reachability & NAT** — finds your public mapping and estimates the NAT type (endpoint‑independent "cone" vs address‑dependent "symmetric").
- **TURN over UDP** — `turn:host:3478?transport=udp`
- **TURN over TCP** — `turn:host:3478?transport=tcp`
- **TURN over TLS** — `turns:host:5349?transport=tcp`

From the combination it renders a **verdict**, e.g.:

| Result | Meaning |
| --- | --- |
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
- A TURN probe only proves **allocation** (control path). It does not measure sustained relay throughput.
