/* ============================================================
   TURN Doctor — client-side WebRTC ICE prober
   ============================================================ */
'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const enc = (s) => new TextEncoder().encode(s);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

const STATUS_ICON = { idle: 'i-dashed', running: 'i-loader', pass: 'i-check', fail: 'i-x', warn: 'i-alert' };
const STATUS_LABEL = { idle: 'Idle', running: 'Running', pass: 'Pass', fail: 'Fail', warn: 'Warn' };

const TEST_DEFS = [
  { key: 'stun', name: 'STUN reachability & NAT', want: 'srflx' },
  { key: 'udp', name: 'TURN over UDP', want: 'relay' },
  { key: 'tcp', name: 'TURN over TCP', want: 'relay' },
  { key: 'flow', name: 'TURN relay data flow', want: 'data' },
  { key: 'tls', name: 'TURN over TLS', want: 'relay' }, // off by default, often slow/timeouts
  { key: 'loss', name: 'Relay packet loss & jitter', want: 'data' },
  { key: 'mtu', name: 'Relay payload size (MTU)', want: 'data' },
  { key: 'soak', name: 'Relay soak — sustained flow', want: 'data' },
  { key: 'gaps', name: 'TURN lifetime & silence gaps', want: 'data' },
];

// Probes that stand up a relay↔relay pair and push bytes through it. They all
// need a credential (no allocation without auth) and at least one transport.
const DATA_PROBES = ['flow', 'loss', 'mtu', 'soak', 'gaps'];
const FLOW_TRANSPORTS = ['udp', 'tcp', 'tls'];

const NAT_FALLBACK_STUN = ['stun:stun.cloudflare.com:3478', 'stun:stun1.l.google.com:19302'];
const PROBE_TIMEOUT = 9000;

/* Loss/jitter probe: unreliable DataChannel, so a transient drop stays visible
   instead of being repaired by SCTP retransmission the way production RTP never
   would be. */
const LOSS_PINGS = 40;
const LOSS_INTERVAL = 90;
const LOSS_DRAIN = 1500;

/* A freshly opened relay is slow for the first few packets — SCTP slow start
   plus the TURN permission being set up — with round trips an order of
   magnitude above steady state (measured ~300 ms settling to ~13 ms). Priming
   the path before measuring keeps that startup cost out of the jitter figure,
   which would otherwise report a healthy relay as degraded. */
const RELAY_WARMUP = 8;

/* MTU probe: payload sizes bracketing a typical RTP video packet (~1200 B) and
   the classic 1500 B Ethernet MTU, plus sizes past it to find the cliff. */
const MTU_SIZES = [100, 500, 1000, 1200, 1400, 1500, 2000, 4000];
const MTU_TIMEOUT = 2500;

const DEFAULT_SOAK_SECONDS = 60;
const SOAK_TICK = 1000;
const DEFAULT_GAP_MARKS = '30,60,120';
const GAP_ECHO_TIMEOUT = 6000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Apple's WebKit (desktop Safari and every browser on iOS/iPadOS) does not expose
// ICE error codes on onicecandidateerror, so a credential-less TURN probe can't
// see the 401 that proves reachability. Detect it to word the message correctly.
const BROWSER_HIDES_ICE_ERRORS = (function () {
  const ua = navigator.userAgent || '';
  const isIOS = /iP(hone|ad|od)/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const isDesktopSafari = /Safari/.test(ua) && !/Chrome|Chromium|CriOS|FxiOS|Edg|OPR|Android/.test(ua);
  return isIOS || isDesktopSafari;
})();

/* ---------------- credential helpers ---------------- */
async function restCredential(secret, ttl, suffix) {
  const now = Math.floor(Date.now() / 1000);
  const expiry = now + (Number(ttl) || 3600);
  const username = suffix ? `${expiry}:${suffix}` : `${expiry}`;
  const key = await crypto.subtle.importKey('raw', enc(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc(username));
  const password = btoa(String.fromCharCode.apply(null, new Uint8Array(sig)));
  return { username, password };
}

async function resolveCredential() {
  const mode = state.authMode;
  if (mode === 'direct') {
    const u = val('username'), p = val('password');
    if (u && p) return { username: u, password: p, provided: true };
    return { username: '.', password: '.', provided: false };
  }
  const secret = val('sharedSecret');
  if (!secret) return { username: '.', password: '.', provided: false };
  if (!window.crypto || !crypto.subtle) {
    throw new Error('Web Crypto is unavailable. Open this page over HTTPS to derive credentials from a shared secret, or switch to Direct credential.');
  }
  const c = await restCredential(secret, val('ttl'), val('suffix').trim());
  return { username: c.username, password: c.password, provided: true };
}

/* ---------------- the core ICE probe ---------------- */
function probe({ iceServers, policy, want, timeout = PROBE_TIMEOUT }) {
  return new Promise((resolve) => {
    const res = { candidates: [], errors: [], gotWanted: false, firstMs: null, gatherMs: null, timedOut: false };
    let pc;
    try {
      pc = new RTCPeerConnection({ iceServers, iceTransportPolicy: policy });
    } catch (e) {
      res.errors.push({ errorText: 'PeerConnection init failed: ' + e.message });
      resolve(res);
      return;
    }
    const t0 = performance.now();
    let done = false;
    let to;
    const finish = () => {
      if (done) return;
      done = true;
      res.gatherMs = Math.round(performance.now() - t0);
      clearTimeout(to);
      try { pc.close(); } catch (e) {}
      resolve(res);
    };
    pc.onicecandidate = (e) => {
      if (!e.candidate || !e.candidate.candidate) { finish(); return; }
      const c = e.candidate;
      res.candidates.push({
        type: c.type,
        protocol: c.protocol,
        address: c.address,
        port: c.port,
        related: c.relatedAddress ? `${c.relatedAddress}:${c.relatedPort}` : null,
      });
      if (c.type === want && !res.gotWanted) {
        res.gotWanted = true;
        res.firstMs = Math.round(performance.now() - t0);
        if (want === 'relay') finish(); // relay found: no need to wait further
      }
    };
    pc.onicecandidateerror = (e) => {
      res.errors.push({ url: e.url, errorCode: e.errorCode, errorText: e.errorText, address: e.address, port: e.port });
    };
    to = setTimeout(() => { res.timedOut = true; finish(); }, timeout);
    try {
      pc.createDataChannel('probe');
      pc.createOffer().then((o) => pc.setLocalDescription(o)).catch((e) => {
        res.errors.push({ errorText: 'createOffer failed: ' + e.message });
        finish();
      });
    } catch (e) {
      res.errors.push({ errorText: e.message });
      finish();
    }
  });
}

/* ---------------- relay pair setup ----------------
   Allocating a relay candidate only proves the server answered the Allocate
   over the control port (3478) — the relay address is minted from that reply
   before any byte crosses the relay port range. To prove the relay actually
   carries media, stand up two PeerConnections in this browser, force BOTH to
   iceTransportPolicy: 'relay', wire them together, and push bytes through.

   This helper only *establishes* the pair and hands it back OPEN, so the flow,
   loss, MTU, soak and gap probes all drive the same setup instead of each one
   duplicating the negotiation dance. The caller owns closing it via
   closeRelayPair(). Side B echoes whatever it receives, so every probe can just
   send and measure the round trip. */
function establishRelayPair({ iceServers, timeout = 12000, label = 'turndoctor', dcOptions = null }) {
  return new Promise((resolve) => {
    const out = {
      ok: false, a: null, b: null, dc: null, connected: false,
      aRelay: null, bRelay: null, errors: [], candidates: [],
      openMs: null, timedOut: false,
    };
    const t0 = performance.now();
    let a, b, dc, to, done = false;
    const settle = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(to);
      out.ok = ok;
      out.openMs = Math.round(performance.now() - t0);
      out.a = a; out.b = b; out.dc = dc;
      if (!ok) closeRelayPair(out);
      resolve(out);
    };
    try {
      a = new RTCPeerConnection({ iceServers, iceTransportPolicy: 'relay' });
      b = new RTCPeerConnection({ iceServers, iceTransportPolicy: 'relay' });
    } catch (e) {
      out.errors.push({ errorText: 'PeerConnection init failed: ' + e.message });
      try { a && a.close(); } catch (_) {}
      try { b && b.close(); } catch (_) {}
      resolve(out);
      return;
    }
    // Trickle candidates between the two peers, buffering until the far side has
    // a remote description (addIceCandidate before that would be rejected).
    const ready = { a: false, b: false };
    const queue = { a: [], b: [] };
    const peerFor = { a: () => b, b: () => a };
    const flush = (side) => {
      const dst = peerFor[side]();
      queue[side].forEach((c) => dst.addIceCandidate(c).catch(() => {}));
      queue[side] = [];
    };
    const wire = (pc, side) => {
      pc.onicecandidate = (e) => {
        if (!e.candidate || !e.candidate.candidate) return;
        const c = e.candidate;
        if (c.type === 'relay') {
          if (side === 'a' && !out.aRelay) out.aRelay = c.address + ':' + c.port;
          if (side === 'b' && !out.bRelay) out.bRelay = c.address + ':' + c.port;
          out.candidates.push({ type: c.type, protocol: c.protocol, address: c.address, port: c.port });
        }
        if (ready[side === 'a' ? 'b' : 'a']) peerFor[side]().addIceCandidate(c).catch(() => {});
        else queue[side].push(c);
      };
      pc.onicecandidateerror = (e) => { if (e.errorCode) out.errors.push({ url: e.url, errorCode: e.errorCode, errorText: e.errorText }); };
      pc.onconnectionstatechange = () => { if (pc.connectionState === 'connected') out.connected = true; };
    };
    wire(a, 'a');
    wire(b, 'b');

    dc = dcOptions ? a.createDataChannel(label, dcOptions) : a.createDataChannel(label);
    dc.binaryType = 'arraybuffer';
    dc.onopen = () => settle(true);
    // Plain echo: bounce every payload back untouched so the caller decides what
    // the message means (ping, sequence number, size sample…).
    b.ondatachannel = (e) => {
      const ch = e.channel;
      ch.binaryType = 'arraybuffer';
      ch.onmessage = (m) => { try { ch.send(m.data); } catch (e2) {} };
    };

    (async () => {
      try {
        const offer = await a.createOffer();
        await a.setLocalDescription(offer);
        await b.setRemoteDescription(offer);
        ready.b = true; flush('a');
        const answer = await b.createAnswer();
        await b.setLocalDescription(answer);
        await a.setRemoteDescription(answer);
        ready.a = true; flush('b');
      } catch (e) {
        out.errors.push({ errorText: 'negotiation failed: ' + e.message });
        settle(false);
      }
    })();

    to = setTimeout(() => { out.timedOut = true; settle(false); }, timeout);
  });
}

function closeRelayPair(pair) {
  if (!pair) return;
  try { pair.dc && pair.dc.close(); } catch (e) {}
  try { pair.a && pair.a.close(); } catch (e) {}
  try { pair.b && pair.b.close(); } catch (e) {}
}

/* Which path did ICE actually pick? relayProtocol on the local candidate is how
   the browser reaches the TURN server (udp/tcp/tls) — the answer to "was my
   TURNS/443 really exercised, or did UDP win again?". */
async function selectedPathStats(pc) {
  if (!pc) return null;
  let stats;
  try { stats = await pc.getStats(); } catch (e) { return null; }
  let pair = null;
  stats.forEach((r) => {
    if (r.type !== 'candidate-pair') return;
    if (r.state === 'succeeded' && (r.nominated || r.selected)) pair = r;
    else if (!pair && r.state === 'succeeded') pair = r;
  });
  if (!pair) return null;
  const local = stats.get ? stats.get(pair.localCandidateId) : null;
  return {
    bytesSent: pair.bytesSent || 0,
    bytesReceived: pair.bytesReceived || 0,
    rttMs: pair.currentRoundTripTime != null ? Math.round(pair.currentRoundTripTime * 1000) : null,
    requestsSent: pair.requestsSent || 0,
    responsesReceived: pair.responsesReceived || 0,
    relayProtocol: local ? (local.relayProtocol || null) : null,
    address: local ? local.address : null,
    port: local ? local.port : null,
  };
}

/* Drive a few serialized round trips so the relay reaches steady state before
   anything is measured. Returns how many of them actually echoed, which doubles
   as a cheap "is this path alive at all" signal. */
async function warmUpRelay(dc, n = RELAY_WARMUP) {
  let ok = 0;
  for (let i = 0; i < n; i++) {
    const ms = await echoOnce(dc, 'warm:' + i, 2000);
    if (ms != null) ok++;
  }
  return ok;
}

/* Round-trip echo helper shared by the data probes: send `payload`, resolve with
   the elapsed ms when the same payload comes back, or null on timeout. */
function echoOnce(dc, payload, timeout) {
  return new Promise((resolve) => {
    if (!dc || dc.readyState !== 'open') { resolve(null); return; }
    const t0 = performance.now();
    let to;
    const onMsg = (m) => {
      const got = typeof m.data === 'string' ? m.data : new TextDecoder().decode(m.data);
      if (got !== payload) return;
      cleanup();
      resolve(Math.round(performance.now() - t0));
    };
    const cleanup = () => { clearTimeout(to); dc.removeEventListener('message', onMsg); };
    dc.addEventListener('message', onMsg);
    to = setTimeout(() => { cleanup(); resolve(null); }, timeout);
    try { dc.send(payload); } catch (e) { cleanup(); resolve(null); }
  });
}

/* ---------------- probe: data flow, per transport ----------------
   The old version handed all three URLs to one RTCPeerConnection. With both
   peers on iceTransportPolicy: 'relay' the ICE agent still gathers relay
   candidates from every transport, but libwebrtc's type preference orders
   relay UDP > TCP > TLS, so the nominated pair is essentially always UDP.
   A server with healthy UDP but a broken TCP or TLS data path reported a clean
   "verified end to end" — a false negative on exactly the two transports that
   matter for restrictive corporate clients. Probing one transport at a time is
   the only way to hold each data path to account. */
async function flowProbe({ enabled, cred }) {
  const res = { perTransport: [], candidates: [], errors: [], firstMs: null, gatherMs: null, timedOut: false };
  const t0 = performance.now();
  for (const key of FLOW_TRANSPORTS) {
    if (!enabled[key]) { res.perTransport.push({ key, ran: false }); continue; }
    const iceServers = [{ urls: turnUrl(key), username: cred.username, credential: cred.password }];
    const pair = await establishRelayPair({ iceServers, label: 'turndoctor-flow-' + key });
    const row = {
      key, ran: true, dataOk: false, connected: pair.connected,
      aRelay: pair.aRelay, bRelay: pair.bRelay, ms: null,
      timedOut: pair.timedOut, path: null,
    };
    if (pair.ok) {
      const ms = await echoOnce(pair.dc, 'flow-' + key, 6000);
      if (ms != null) { row.dataOk = true; row.ms = ms; }
      row.path = await selectedPathStats(pair.a);
      row.connected = true;
    }
    pair.candidates.forEach((c) => res.candidates.push({ ...c, transport: key }));
    pair.errors.forEach((e) => res.errors.push({ ...e, transport: key }));
    closeRelayPair(pair);
    res.perTransport.push(row);
    if (row.dataOk && res.firstMs == null) res.firstMs = row.ms;
  }
  res.gatherMs = Math.round(performance.now() - t0);
  return res;
}

/* ---------------- probe: packet loss & jitter ----------------
   The flow probe uses a default (reliable, ordered) DataChannel, so SCTP
   retransmits anything the network drops — a multi-second loss window is
   invisible there while production RTP, which has no such safety net, would
   glitch. Here the channel is unreliable and unordered, so drops stay drops. */
async function lossProbe({ iceServers }) {
  const res = { ran: true, sent: 0, received: 0, lossPct: null, rtts: [], jitterMs: null,
                minMs: null, maxMs: null, avgMs: null, path: null, aRelay: null, bRelay: null,
                candidates: [], errors: [], firstMs: null, gatherMs: null, timedOut: false, setupFailed: false };
  const t0 = performance.now();
  const pair = await establishRelayPair({
    iceServers, label: 'turndoctor-loss', dcOptions: { ordered: false, maxRetransmits: 0 },
  });
  res.candidates = pair.candidates; res.errors = pair.errors;
  res.aRelay = pair.aRelay; res.bRelay = pair.bRelay; res.timedOut = pair.timedOut;
  if (!pair.ok) { res.setupFailed = true; res.gatherMs = Math.round(performance.now() - t0); closeRelayPair(pair); return res; }
  await warmUpRelay(pair.dc);

  const seen = {};
  const sentAt = {};
  const onMsg = (m) => {
    const got = typeof m.data === 'string' ? m.data : new TextDecoder().decode(m.data);
    if (got.indexOf('seq:') !== 0 || seen[got]) return;
    seen[got] = true;
    const t = sentAt[got];
    if (t != null) res.rtts.push(Math.round(performance.now() - t));
  };
  pair.dc.addEventListener('message', onMsg);

  for (let i = 0; i < LOSS_PINGS; i++) {
    const payload = 'seq:' + i;
    sentAt[payload] = performance.now();
    try { pair.dc.send(payload); res.sent++; } catch (e) {}
    await sleep(LOSS_INTERVAL);
  }
  await sleep(LOSS_DRAIN); // let stragglers arrive before scoring
  pair.dc.removeEventListener('message', onMsg);

  res.received = res.rtts.length;
  res.lossPct = res.sent ? Math.round(((res.sent - res.received) / res.sent) * 1000) / 10 : null;
  if (res.rtts.length) {
    res.minMs = Math.min.apply(null, res.rtts);
    res.maxMs = Math.max.apply(null, res.rtts);
    res.avgMs = Math.round(res.rtts.reduce((a, b) => a + b, 0) / res.rtts.length);
    res.firstMs = res.rtts[0];
    // RFC 3550 §A.8 smoothing, applied to round-trip variation. There is no
    // synchronised clock between the two ends here (same browser, echoed back),
    // so this tracks RTT jitter — a proxy for one-way jitter, not a substitute.
    let j = 0;
    for (let i = 1; i < res.rtts.length; i++) j += (Math.abs(res.rtts[i] - res.rtts[i - 1]) - j) / 16;
    res.jitterMs = Math.round(j * 10) / 10;
  }
  res.path = await selectedPathStats(pair.a);
  closeRelayPair(pair);
  res.gatherMs = Math.round(performance.now() - t0);
  return res;
}

/* ---------------- probe: payload size / MTU cliff ----------------
   Everything the reachability probes exchange is small (STUN, ~100 B). A path
   that forwards small control packets but silently drops ~1200 B RTP-sized ones
   looks perfectly healthy to them and produces rp=0/rb=0 on the server. NAT 1:1
   plus edge DNAT is exactly the topology where the effective MTU shrinks and
   PMTUD breaks (stateful firewalls often swallow the ICMP that would fix it). */
async function mtuProbe({ iceServers }) {
  const res = { ran: true, samples: [], largestOk: null, firstFail: null, path: null,
                aRelay: null, bRelay: null, candidates: [], errors: [],
                firstMs: null, gatherMs: null, timedOut: false, setupFailed: false };
  const t0 = performance.now();
  const pair = await establishRelayPair({
    iceServers, label: 'turndoctor-mtu', dcOptions: { ordered: false, maxRetransmits: 0 },
  });
  res.candidates = pair.candidates; res.errors = pair.errors;
  res.aRelay = pair.aRelay; res.bRelay = pair.bRelay; res.timedOut = pair.timedOut;
  if (!pair.ok) { res.setupFailed = true; res.gatherMs = Math.round(performance.now() - t0); closeRelayPair(pair); return res; }
  await warmUpRelay(pair.dc);

  for (const size of MTU_SIZES) {
    // Marker keeps each payload unique so echoes can't be confused across sizes.
    const marker = 'mtu' + size + ':';
    const payload = marker + 'x'.repeat(Math.max(0, size - marker.length));
    const ms = await echoOnce(pair.dc, payload, MTU_TIMEOUT);
    res.samples.push({ size, ok: ms != null, ms });
    if (ms != null) { res.largestOk = size; if (res.firstMs == null) res.firstMs = ms; }
    else if (res.firstFail == null) res.firstFail = size;
    await sleep(60);
  }
  res.path = await selectedPathStats(pair.a);
  closeRelayPair(pair);
  res.gatherMs = Math.round(performance.now() - t0);
  return res;
}

/* ---------------- probe: soak / sustained flow ----------------
   The incident this tool chases is intermittent — degradation in time windows.
   A ~100 ms echo has almost no chance of landing inside one. Holding the relay
   open for minutes and sampling getStats every second produces a timeline that
   can be lined up against the coturn logs by timestamp. */
async function soakProbe({ iceServers, seconds, onTick }) {
  const res = { ran: true, seconds, ticks: [], stalls: 0, longestStallS: 0, pings: 0, pongs: 0,
                path: null, aRelay: null, bRelay: null, candidates: [], errors: [],
                firstMs: null, gatherMs: null, timedOut: false, setupFailed: false };
  const t0 = performance.now();
  const pair = await establishRelayPair({
    iceServers, label: 'turndoctor-soak', dcOptions: { ordered: false, maxRetransmits: 0 },
  });
  res.candidates = pair.candidates; res.errors = pair.errors;
  res.aRelay = pair.aRelay; res.bRelay = pair.bRelay; res.timedOut = pair.timedOut;
  if (!pair.ok) { res.setupFailed = true; res.gatherMs = Math.round(performance.now() - t0); closeRelayPair(pair); return res; }
  await warmUpRelay(pair.dc);

  let pongs = 0;
  const onMsg = (m) => {
    const got = typeof m.data === 'string' ? m.data : new TextDecoder().decode(m.data);
    if (got.indexOf('soak:') === 0) pongs++;
  };
  pair.dc.addEventListener('message', onMsg);

  let prev = await selectedPathStats(pair.a);
  let stallRun = 0;
  for (let t = 1; t <= seconds; t++) {
    const before = pongs;
    try { pair.dc.send('soak:' + t); res.pings++; } catch (e) {}
    await sleep(SOAK_TICK);
    const now = await selectedPathStats(pair.a);
    const deltaBytes = (now && prev) ? Math.max(0, now.bytesReceived - prev.bytesReceived) : 0;
    const echoed = pongs > before;
    if (!echoed) { res.stalls++; stallRun++; if (stallRun > res.longestStallS) res.longestStallS = stallRun; }
    else stallRun = 0;
    const tick = { t, bytes: deltaBytes, rttMs: now ? now.rttMs : null, echoed };
    res.ticks.push(tick);
    if (onTick) onTick(tick, seconds);
    prev = now;
  }
  pair.dc.removeEventListener('message', onMsg);
  res.pongs = pongs;
  res.path = await selectedPathStats(pair.a);
  if (res.ticks.length) { const f = res.ticks.find((k) => k.rttMs != null); res.firstMs = f ? f.rttMs : null; }
  closeRelayPair(pair);
  res.gatherMs = Math.round(performance.now() - t0);
  return res;
}

/* ---------------- probe: lifetime & silence gaps ----------------
   Where the first failure lands in time names the culprit. RFC 8656: permission
   lifetime 5 min, channel binding and allocation 10 min. A break at 30–120 s is
   firewall/conntrack; at ~300 s a permission expiring un-refreshed; at ~600 s
   the allocation or channel bind. Three different fixes.

   Caveat worth keeping in mind: ICE consent freshness (RFC 8445 §11) keeps
   probing the selected pair roughly every 5 s, so the silence is never total at
   the network layer — this bounds, rather than invalidates, the result. */
async function gapsProbe({ iceServers, marks, onMark }) {
  const res = { ran: true, marks: [], firstFailS: null, path: null,
                aRelay: null, bRelay: null, candidates: [], errors: [],
                firstMs: null, gatherMs: null, timedOut: false, setupFailed: false };
  const t0 = performance.now();
  const pair = await establishRelayPair({
    iceServers, label: 'turndoctor-gaps', dcOptions: { ordered: false, maxRetransmits: 0 },
  });
  res.candidates = pair.candidates; res.errors = pair.errors;
  res.aRelay = pair.aRelay; res.bRelay = pair.bRelay; res.timedOut = pair.timedOut;
  if (!pair.ok) { res.setupFailed = true; res.gatherMs = Math.round(performance.now() - t0); closeRelayPair(pair); return res; }
  await warmUpRelay(pair.dc);

  // Baseline: the path must work before a silence can be blamed for breaking it.
  const base = await echoOnce(pair.dc, 'gap:0', GAP_ECHO_TIMEOUT);
  res.marks.push({ seconds: 0, ok: base != null, ms: base });
  if (onMark) onMark(res.marks[0]);
  res.firstMs = base;

  if (base != null) {
    for (const g of marks) {
      if (onMark) onMark({ seconds: g, pending: true });
      await sleep(g * 1000);
      const ms = await echoOnce(pair.dc, 'gap:' + g, GAP_ECHO_TIMEOUT);
      const row = { seconds: g, ok: ms != null, ms };
      res.marks.push(row);
      if (onMark) onMark(row);
      if (ms == null && res.firstFailS == null) { res.firstFailS = g; break; }
    }
  }
  res.path = await selectedPathStats(pair.a);
  closeRelayPair(pair);
  res.gatherMs = Math.round(performance.now() - t0);
  return res;
}

function evaluateFlow(res) {
  const ran = res.perTransport.filter((r) => r.ran);
  const ok = ran.filter((r) => r.dataOk);
  if (!ran.length) return { status: 'warn', kind: 'noalloc' };
  if (ok.length === ran.length) return { status: 'pass', kind: 'flow' };
  if (ok.length) return { status: 'warn', kind: 'mixed' };
  // Nothing carried data. Distinguish "allocated but nothing crossed" (relay
  // port range / peer ACL) from "never allocated" (auth or unreachable).
  const anyAlloc = ran.some((r) => r.aRelay && r.bRelay);
  const authErr = res.errors.some((e) => { const c = Number(e.errorCode); return c === 401 || c === 403; });
  if (anyAlloc) return { status: 'fail', kind: 'noflow' };
  if (authErr) return { status: 'fail', kind: 'auth' };
  return { status: 'fail', kind: 'noalloc' };
}

const TRANSPORT_LABEL = { udp: 'UDP', tcp: 'TCP', tls: 'TLS' };

function flowTable(rows) {
  const body = rows.map((r) => {
    if (!r.ran) return `<tr><td>${TRANSPORT_LABEL[r.key]}</td><td colspan="3" style="color:var(--faint)">not enabled</td></tr>`;
    const via = r.path && r.path.relayProtocol ? r.path.relayProtocol : '—';
    const verdict = r.dataOk
      ? `<span class="ctype ctype-relay">data ok</span>`
      : r.connected ? `<span class="ctype ctype-prflx">no echo</span>` : `<span class="ctype ctype-fail">no relay</span>`;
    return `<tr><td>${TRANSPORT_LABEL[r.key]}</td><td>${verdict}</td><td>${r.ms != null ? r.ms + ' ms' : '—'}</td><td>${esc(via)}</td></tr>`;
  }).join('');
  return `<table class="cand-table"><thead><tr><th>Transport</th><th>Result</th><th>Echo</th><th>Via</th></tr></thead><tbody>${body}</tbody></table>`;
}

function explainFlow(evalRes, res) {
  const table = flowTable(res.perTransport);
  const note = ` Each transport is probed <b>on its own</b> — handing all URLs to one connection lets relay UDP win the ICE priority every time, hiding a broken TCP or TLS data path behind a passing UDP one.`;
  if (evalRes.kind === 'flow') {
    const list = res.perTransport.filter((r) => r.ran).map((r) => TRANSPORT_LABEL[r.key]).join(', ');
    return { tone: 'pass', html: `Data crossed the relay <b>end to end on every enabled transport</b> (${esc(list)}). For each one, two peers were forced to <code>iceTransportPolicy: relay</code>, both allocated a relay, and a <code>DataChannel</code> echoed through it — proving the relay carries media, not just that an allocation address was handed out.${note}${table}` };
  }
  if (evalRes.kind === 'mixed') {
    const good = res.perTransport.filter((r) => r.ran && r.dataOk).map((r) => TRANSPORT_LABEL[r.key]);
    const bad = res.perTransport.filter((r) => r.ran && !r.dataOk).map((r) => TRANSPORT_LABEL[r.key]);
    return { tone: 'warn', html: `Data crossed the relay over <b>${esc(good.join(', '))}</b> but <b>not over ${esc(bad.join(', '))}</b>. The relay works, yet clients restricted to the failing transport(s) cannot use it. If <b>TLS</b> is among the failures, corporate/DPI networks — the very ones that need TURNS — will fail while your own tests look healthy.${note}${table}` };
  }
  if (evalRes.kind === 'noflow') {
    return { tone: 'fail', html: `Relays were <b>allocated</b> but <b>no data crossed them</b> on any transport${res.timedOut ? ' (timed out)' : ''}. The allocation succeeds over the control port, yet media can't flow through the relay port. Classic causes: the coturn relay port range (<code>min-port</code>–<code>max-port</code>, e.g. <code>49152–65535/UDP</code>) isn't open inbound on the TURN public IP, or <code>allowed-peer-ip</code> denies the peer. <b>This is exactly the failure an allocation-only check cannot see</b>, and it is the signature that shows up as <code>rp=0/rb=0</code> in the coturn session logs.${table}` };
  }
  if (evalRes.kind === 'auth') {
    return { tone: 'fail', html: `The relay couldn't be allocated because the <b>credential was rejected</b> (401/403). Fix the shared secret / TTL / username-password, then re-run.${table}` };
  }
  return { tone: 'fail', html: `Couldn't establish a working relay pair on any transport${res.timedOut ? ' (timed out)' : ''}. If the per-transport reachability probes passed but this didn't, the server hands out allocation addresses but a usable relay path couldn't be set up from here.${table}` };
}

/* ---------------- loss / jitter ---------------- */
function evaluateLoss(res) {
  if (res.setupFailed) return { status: 'fail', kind: 'nosetup' };
  if (!res.received) return { status: 'fail', kind: 'nodata' };
  if (res.lossPct >= 5) return { status: 'fail', kind: 'lossy' };
  if (res.lossPct > 0 || (res.jitterMs != null && res.jitterMs >= 30)) return { status: 'warn', kind: 'degraded' };
  return { status: 'pass', kind: 'clean' };
}

function lossStats(res) {
  if (!res.received) return '';
  return `<table class="cand-table"><thead><tr><th>Sent</th><th>Received</th><th>Loss</th><th>RTT min/avg/max</th><th>Jitter</th></tr></thead>
    <tbody><tr><td>${res.sent}</td><td>${res.received}</td><td>${res.lossPct}%</td>
    <td>${res.minMs}/${res.avgMs}/${res.maxMs} ms</td><td>${res.jitterMs} ms</td></tr></tbody></table>`;
}

function explainLoss(evalRes, res) {
  const via = res.path && res.path.relayProtocol ? ` The path ICE selected reached the TURN server over <b>${esc(res.path.relayProtocol)}</b>.` : '';
  const why = ` This probe uses an <b>unreliable, unordered</b> <code>DataChannel</code> (<code>maxRetransmits: 0</code>) on purpose: the standard reliable channel would retransmit whatever the network drops, hiding exactly the loss that makes production RTP glitch.`;
  if (evalRes.kind === 'clean') {
    return { tone: 'pass', html: `<b>No loss</b> across ${res.sent} unreliable packets through the relay, jitter ${res.jitterMs} ms.${via}${why}${lossStats(res)}` };
  }
  if (evalRes.kind === 'degraded') {
    return { tone: 'warn', html: `<b>${res.lossPct}% loss</b> and <b>${res.jitterMs} ms jitter</b> over ${res.sent} packets. Low but non-zero loss on an idle test is a warning sign — under real media load it typically gets worse. Re-run a few times: if it comes and goes, that matches an intermittent relay path rather than a hard fault.${via}${why}${lossStats(res)}` };
  }
  if (evalRes.kind === 'lossy') {
    return { tone: 'fail', html: `<b>${res.lossPct}% of packets were lost</b> crossing the relay (${res.received}/${res.sent} returned), jitter ${res.jitterMs} ms. This is enough to break real-time media. Because the channel is unreliable, this is genuine network loss — not a retransmission artefact.${via}${why}${lossStats(res)}` };
  }
  if (evalRes.kind === 'nodata') {
    return { tone: 'fail', html: `The relay pair came up but <b>not one of ${res.sent} packets returned</b>. Combined with a successful allocation, that is the <code>rp=0/rb=0</code> signature: the control path works and the data path does not.${why}` };
  }
  return { tone: 'fail', html: `Couldn't establish a relay pair for the loss test${res.timedOut ? ' (timed out)' : ''}. Fix the credential or transport first — the per-transport probes above say which.` };
}

/* ---------------- MTU ---------------- */
function evaluateMtu(res) {
  if (res.setupFailed) return { status: 'fail', kind: 'nosetup' };
  if (!res.largestOk) return { status: 'fail', kind: 'nodata' };
  if (res.firstFail == null) return { status: 'pass', kind: 'clean' };
  // Anything that drops below a typical RTP video packet is a real problem.
  if (res.firstFail <= 1200) return { status: 'fail', kind: 'small' };
  return { status: 'warn', kind: 'cliff' };
}

function mtuTable(res) {
  const rows = res.samples.map((s) => `<tr><td>${s.size} B</td>
    <td>${s.ok ? '<span class="ctype ctype-relay">ok</span>' : '<span class="ctype ctype-fail">dropped</span>'}</td>
    <td>${s.ms != null ? s.ms + ' ms' : '—'}</td></tr>`).join('');
  return `<table class="cand-table"><thead><tr><th>Payload</th><th>Result</th><th>Echo</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function explainMtu(evalRes, res) {
  const caveat = ` <b>Read this as a hint, not a measurement.</b> A <code>DataChannel</code> runs over SCTP, which does its own fragmentation and reassembly, so a lower-layer UDP fragmentation problem can be partly masked. The browser exposes no raw socket and no DF bit — a definitive answer needs <code>ping -M do -s &lt;size&gt;</code> from a host on the affected segment.`;
  if (evalRes.kind === 'clean') {
    return { tone: 'pass', html: `Every payload up to <b>${res.largestOk} B</b> crossed the relay, including RTP-sized (1200 B) and full-MTU (1500 B) packets. No size cliff on this path.${caveat}${mtuTable(res)}` };
  }
  if (evalRes.kind === 'small') {
    return { tone: 'fail', html: `Payloads stop crossing at <b>${res.firstFail} B</b> — below the ~1200 B of a typical RTP video packet (largest that made it: <b>${res.largestOk} B</b>). Small control packets pass while real media does not, which is precisely how a path produces successful allocations and <code>rp=0/rb=0</code> sessions. NAT 1:1 plus edge DNAT is a classic trigger: the effective MTU shrinks and PMTUD breaks when the firewall drops the ICMP that would signal it.${caveat}${mtuTable(res)}` };
  }
  if (evalRes.kind === 'cliff') {
    return { tone: 'warn', html: `Payloads cross up to <b>${res.largestOk} B</b> but fail from <b>${res.firstFail} B</b>. RTP-sized packets still get through, so ordinary media should work, but the headroom is thinner than a clean path — worth checking the MTU end to end if you also see loss.${caveat}${mtuTable(res)}` };
  }
  if (evalRes.kind === 'nodata') {
    return { tone: 'fail', html: `Not even a 100-byte payload crossed the relay. The size dimension can't be assessed until basic data flow works — see the data-flow and loss probes.` };
  }
  return { tone: 'fail', html: `Couldn't establish a relay pair for the payload-size test${res.timedOut ? ' (timed out)' : ''}.` };
}

/* ---------------- soak ---------------- */
function evaluateSoak(res) {
  if (res.setupFailed) return { status: 'fail', kind: 'nosetup' };
  if (!res.pongs) return { status: 'fail', kind: 'nodata' };
  if (res.longestStallS >= 3) return { status: 'fail', kind: 'stalled' };
  if (res.stalls) return { status: 'warn', kind: 'blips' };
  return { status: 'pass', kind: 'steady' };
}

// Compact SVG sparkline of per-second echo health: a filled bar per tick,
// muted when the second echoed and red when it didn't.
function sparkline(ticks) {
  if (!ticks.length) return '';
  const W = 100, H = 26, n = ticks.length;
  const bw = W / n;
  const rtts = ticks.map((t) => t.rttMs).filter((v) => v != null);
  const max = rtts.length ? Math.max.apply(null, rtts) : 1;
  const bars = ticks.map((t, i) => {
    const h = t.echoed ? Math.max(2, ((t.rttMs != null ? t.rttMs : 1) / (max || 1)) * (H - 2)) : H;
    const fill = t.echoed ? 'var(--accent)' : 'var(--fail)';
    const op = t.echoed ? '0.75' : '1';
    return `<rect x="${(i * bw).toFixed(2)}" y="${(H - h).toFixed(2)}" width="${Math.max(0.6, bw - 0.25).toFixed(2)}" height="${h.toFixed(2)}" fill="${fill}" opacity="${op}"/>`;
  }).join('');
  return `<div class="spark"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Per-second relay echo timeline">${bars}</svg>
    <div class="spark-axis mono"><span>0s</span><span>${n}s</span></div></div>`;
}

function explainSoak(evalRes, res) {
  const via = res.path && res.path.relayProtocol ? ` Path selected: <b>${esc(res.path.relayProtocol)}</b>.` : '';
  const spark = sparkline(res.ticks);
  const why = ` The incident this looks for is <b>intermittent</b> — a sub-second echo has almost no chance of landing inside a bad window. Each bar is one second; height is round-trip time, red means that second produced no echo. Run this at different times of day and line the red bars up against the coturn logs by timestamp.`;
  if (evalRes.kind === 'steady') {
    return { tone: 'pass', html: `The relay carried traffic <b>continuously for ${res.seconds}s</b> — ${res.pongs}/${res.pings} echoes, no stalled second.${via}${why}${spark}` };
  }
  if (evalRes.kind === 'blips') {
    return { tone: 'warn', html: `The relay stayed up for ${res.seconds}s but <b>${res.stalls} second(s) produced no echo</b> (longest run ${res.longestStallS}s), ${res.pongs}/${res.pings} total.${via} Brief blips on an idle path often precede the user-visible drops.${why}${spark}` };
  }
  if (evalRes.kind === 'stalled') {
    return { tone: 'fail', html: `Traffic <b>stalled for up to ${res.longestStallS} consecutive seconds</b> (${res.stalls} bad seconds out of ${res.seconds}, ${res.pongs}/${res.pings} echoes).${via} That is a genuine interruption on the relay path, not a startup artefact — capture the wall-clock time of this run and cross-reference the coturn session logs for <code>rp=0/rb=0</code>.${why}${spark}` };
  }
  if (evalRes.kind === 'nodata') {
    return { tone: 'fail', html: `The relay pair came up but no echo ever returned during the ${res.seconds}s soak — the control path works and the data path does not.` };
  }
  return { tone: 'fail', html: `Couldn't establish a relay pair for the soak test${res.timedOut ? ' (timed out)' : ''}.` };
}

/* ---------------- lifetime / silence gaps ---------------- */
function evaluateGaps(res) {
  if (res.setupFailed) return { status: 'fail', kind: 'nosetup' };
  const base = res.marks[0];
  if (!base || !base.ok) return { status: 'fail', kind: 'nobase' };
  if (res.firstFailS == null) return { status: 'pass', kind: 'survives' };
  if (res.firstFailS <= 120) return { status: 'fail', kind: 'firewall' };
  if (res.firstFailS <= 300) return { status: 'fail', kind: 'permission' };
  return { status: 'fail', kind: 'allocation' };
}

function gapsTable(res) {
  const rows = res.marks.map((m) => `<tr>
    <td>${m.seconds === 0 ? 'baseline' : 'after ' + m.seconds + 's silence'}</td>
    <td>${m.ok ? '<span class="ctype ctype-relay">echo ok</span>' : '<span class="ctype ctype-fail">no echo</span>'}</td>
    <td>${m.ms != null ? m.ms + ' ms' : '—'}</td></tr>`).join('');
  return `<table class="cand-table"><thead><tr><th>Stage</th><th>Result</th><th>Echo</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function explainGaps(evalRes, res) {
  const ref = ` Reference lifetimes (RFC 8656): <b>permission 5 min</b>, <b>channel binding and allocation 10 min</b>. Note that ICE consent freshness keeps probing the selected pair every few seconds, so the silence is never total at the network layer — this bounds the result rather than invalidating it.`;
  if (evalRes.kind === 'survives') {
    const longest = res.marks[res.marks.length - 1];
    return { tone: 'pass', html: `The relay still echoed after <b>every silence tested</b>, up to <b>${longest.seconds}s</b>. Neither an idle-timeout on the path nor an un-refreshed TURN permission is breaking this connection within that window.${ref}${gapsTable(res)}` };
  }
  if (evalRes.kind === 'firewall') {
    return { tone: 'fail', html: `Data stopped flowing after <b>${res.firstFailS}s of silence</b>. That is far short of any TURN lifetime, so the TURN server is not the culprit — something on the path is dropping the idle mapping. Look at <b>firewall/NAT conntrack timeouts</b> on the DNAT device and between the client segment and the TURN VM, and at the client's keepalive interval.${ref}${gapsTable(res)}` };
  }
  if (evalRes.kind === 'permission') {
    return { tone: 'fail', html: `Data stopped flowing after <b>${res.firstFailS}s of silence</b> — right around the <b>5-minute permission lifetime</b>. This points at a TURN <b>permission expiring without being refreshed</b>, rather than a network timeout. Check that the client keeps the permission alive, and look for the corresponding refresh activity in the coturn logs.${ref}${gapsTable(res)}` };
  }
  if (evalRes.kind === 'allocation') {
    return { tone: 'fail', html: `Data stopped flowing after <b>${res.firstFailS}s of silence</b> — around the <b>10-minute allocation / channel-binding lifetime</b>. That suggests the allocation was not refreshed, or the server dropped it early. Inspect the coturn allocation lifetime settings and the refresh traffic in its logs.${ref}${gapsTable(res)}` };
  }
  if (evalRes.kind === 'nobase') {
    return { tone: 'fail', html: `The baseline echo failed before any silence was applied, so there is nothing to time out — fix basic relay data flow first (see the data-flow probe).` };
  }
  return { tone: 'fail', html: `Couldn't establish a relay pair for the lifetime test${res.timedOut ? ' (timed out)' : ''}.` };
}

/* ---------------- per-transport url builders ---------------- */
function turnUrl(key) {
  const host = state.host, port = state.port, tls = state.tlsPort;
  if (key === 'udp') return `turn:${host}:${port}?transport=udp`;
  if (key === 'tcp') return `turn:${host}:${port}?transport=tcp`;
  if (key === 'tls') return `turns:${host}:${tls}?transport=tcp`;
  if (key === 'flow') return `each transport separately · relay ↔ relay`;
  if (key === 'loss') return `${LOSS_PINGS} unreliable packets · relay ↔ relay`;
  if (key === 'mtu') return `payload ${MTU_SIZES[0]}–${MTU_SIZES[MTU_SIZES.length - 1]} B · relay ↔ relay`;
  if (key === 'soak') return `${state.soakSeconds}s sustained · relay ↔ relay`;
  if (key === 'gaps') return `silence ${state.gapMarks}s · relay ↔ relay`;
  return state.stun;
}

// iceServers for the data probes: every enabled TURN transport with the resolved
// credential, mirroring what a real client would offer. The flow probe does NOT
// use this — it deliberately isolates one transport at a time (see flowProbe).
function flowIceServers(enabled, cred) {
  const urls = FLOW_TRANSPORTS.filter((k) => enabled[k]).map((k) => turnUrl(k));
  return [{ urls, username: cred.username, credential: cred.password }];
}

function parseGapMarks(raw) {
  return String(raw || '').split(',')
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => Number.isFinite(n) && n > 0 && n <= 900);
}

/* ---------------- NAT detection (best effort) ---------------- */
async function detectNat(primarySrflx) {
  if (!primarySrflx) return null;
  const fb = NAT_FALLBACK_STUN.find((u) => u !== state.stun) || NAT_FALLBACK_STUN[0];
  const r = await probe({ iceServers: [{ urls: fb }], policy: 'all', want: 'srflx', timeout: 5000 });
  const other = r.candidates.find((c) => c.type === 'srflx');
  if (!other) return { type: 'unknown', label: 'unknown', detail: 'Could not reach a second STUN server to compare mappings.' };
  const sameIp = other.address === primarySrflx.address;
  const samePort = String(other.port) === String(primarySrflx.port);
  if (sameIp && samePort) {
    return { type: 'endpoint-independent', label: 'cone', detail: 'The same public mapping was seen by two different servers, so direct P2P (srflx) is likely to work.' };
  }
  return {
    type: 'address-dependent',
    label: 'symmetric',
    detail: `Your public port changed per destination (${primarySrflx.address}:${primarySrflx.port} vs ${other.address}:${other.port}), so direct P2P usually fails and relay is required.`,
  };
}

/* ---------------- evaluation ---------------- */
function evaluateTurn(res, provided) {
  if (res.gotWanted) return { status: 'pass', kind: 'ok' };
  const has = (code) => res.errors.some((e) => Number(e.errorCode) === code);
  if (has(401) || has(403) || has(438)) {
    // 401 means the packet reached the server and came back: reachable.
    // With credentials, that is an auth failure; without, it is a reachability pass.
    return provided ? { status: 'fail', kind: 'auth' } : { status: 'pass', kind: 'reachable' };
  }
  if (has(701) || res.timedOut) return { status: 'fail', kind: 'unreach' };
  // No relay, no 401/701, no timeout: the server most likely answered but this
  // browser (notably Safari) hides the TURN auth error. Inconclusive without
  // credentials; with credentials it is a genuine failure to allocate a relay.
  return provided ? { status: 'fail', kind: 'unreach' } : { status: 'warn', kind: 'inconclusive' };
}

/* ---------------- rendering ---------------- */
function setStatus(card, status) {
  card.dataset.status = status;
  $('.test-status use', card).setAttribute('href', '#' + STATUS_ICON[status]);
  $('.test-badge', card).textContent = STATUS_LABEL[status];
}

function renderCards(defs) {
  const wrap = $('#tests');
  wrap.innerHTML = '';
  defs.forEach((d, i) => {
    const card = document.createElement('article');
    card.className = 'test';
    card.dataset.status = 'idle';
    card.dataset.key = d.key;
    card.style.animationDelay = (i * 0.05) + 's';
    card.innerHTML = `
      <button class="test-head" type="button" aria-expanded="false">
        <span class="test-status"><svg class="ic" viewBox="0 0 24 24"><use href="#i-dashed"/></svg></span>
        <span class="test-main">
          <span class="test-name">${esc(d.name)}</span>
          <span class="test-sub mono">${esc(d.url)}</span>
        </span>
        <span class="test-meta">
          <span class="test-time mono">—</span>
          <span class="test-badge">Idle</span>
          <svg class="ic test-caret" viewBox="0 0 24 24"><use href="#i-chevron"/></svg>
        </span>
      </button>
      <div class="test-body"></div>`;
    $('.test-head', card).addEventListener('click', () => {
      const open = card.classList.toggle('is-open');
      $('.test-head', card).setAttribute('aria-expanded', String(open));
    });
    wrap.appendChild(card);
  });
}

function candRows(cands) {
  if (!cands.length) return '<tr><td colspan="4" style="color:var(--faint)">No candidates gathered.</td></tr>';
  return cands.map((c) => `
    <tr>
      <td><span class="ctype ctype-${esc(c.type)}">${esc(c.type)}</span></td>
      <td>${esc(c.protocol || '—')}</td>
      <td>${esc(c.address || '(mdns / hidden)')}</td>
      <td>${esc(c.port != null ? c.port : '—')}</td>
    </tr>`).join('');
}

function errRows(errs, passed) {
  let meaningful = errs.filter((e) => e.errorCode || e.errorText);
  // On a successful probe, a 401 is just the reachability signal (already shown
  // in the explanation) and a 701 means one host interface (e.g. a VPN or a
  // virtual NIC) couldn't reach the server while another one did. Show only the
  // 701s, framed as a benign note, deduplicated per server URL.
  if (passed) {
    const seen = {};
    meaningful = meaningful.filter((e) => Number(e.errorCode) === 701 && !seen[e.url || '701'] && (seen[e.url || '701'] = 1));
    if (!meaningful.length) return '';
    return '<p class="data-title">Notes</p>' + meaningful.map((e) => `
      <div class="err-line err-benign"><span class="err-code">701</span><span>A host interface could not reach the server — harmless, another interface succeeded (common with VPNs or multiple network interfaces)${e.url ? ' · ' + esc(e.url) : ''}</span></div>`).join('');
  }
  if (!meaningful.length) return '';
  const label = (e) => {
    const c = Number(e.errorCode);
    if (c === 401) return 'Unauthorized — credential rejected';
    if (c === 403) return 'Forbidden — peer/permission denied';
    if (c === 438) return 'Stale nonce';
    if (c === 701) return 'Could not reach the server — no host interface got a response';
    if (c === 300) return 'Try alternate server';
    return e.errorText || 'ICE error';
  };
  return '<p class="data-title">ICE errors</p>' + meaningful.map((e) => `
    <div class="err-line"><span class="err-code">${esc(e.errorCode || 'ERR')}</span><span>${esc(label(e))}${e.url ? ' · ' + esc(e.url) : ''}</span></div>`).join('');
}

function explainTurn(key, evalRes, res) {
  const url = turnUrl(key);
  const proto = key === 'tls' ? 'TLS' : key.toUpperCase();
  if (evalRes.kind === 'ok') {
    const relay = res.candidates.find((c) => c.type === 'relay');
    return { tone: 'pass', html: `Allocated a <code>relay</code> candidate in ${res.firstMs} ms via <code>${esc(url)}</code>${relay ? ` (relay address <b class="mono">${esc(relay.address)}:${esc(relay.port)}</b>)` : ''}. This transport reaches the TURN server from your network and can carry media.` };
  }
  if (evalRes.kind === 'reachable') {
    return { tone: 'pass', html: `The TURN server is <b>reachable over ${proto}</b> — it answered the allocation request with <code>401</code>, which proves your network lets you reach it on this transport. No credentials were provided, so no relay was allocated. Add a shared secret or credential to verify a full relay allocation.` };
  }
  if (evalRes.kind === 'auth') {
    return { tone: 'fail', html: `The TURN server was reachable but <b>rejected the credential</b> (401/403). The transport itself is not blocked — fix the username/password or the shared secret and TTL, then retry.` };
  }
  if (evalRes.kind === 'inconclusive') {
    const why = BROWSER_HIDES_ICE_ERRORS
      ? `This browser (<b>Safari / WebKit</b>) hides TURN authentication errors`
      : `This browser didn't surface a TURN error`;
    return { tone: 'warn', html: `The probe finished over ${proto} without a relay <b>and without a visible error</b>. ${why}, so reachability can't be confirmed here without credentials. Add a shared secret/credential${BROWSER_HIDES_ICE_ERRORS ? ', or re-run in Chrome or Firefox,' : ''} for a definitive answer.` };
  }
  return { tone: 'fail', html: `No <code>relay</code> candidate was allocated over ${proto}${res.timedOut ? ' (timed out)' : ''}. Either this network blocks ${proto} to the TURN port, or the server is not listening on that transport. If other transports pass, the problem is network filtering on this path.` };
}

function explainStun(evalRes, res, nat) {
  if (evalRes.status !== 'pass') {
    return { tone: 'warn', html: `No <code>srflx</code> candidate was discovered. STUN may be blocked on this network, or the STUN server is unreachable. Public IP could not be determined.` };
  }
  const s = res.candidates.find((c) => c.type === 'srflx');
  let html = `Discovered your public mapping <b class="mono">${esc(s.address)}:${esc(s.port)}</b> in ${res.firstMs} ms — STUN works and outbound UDP is not fully blocked.`;
  if (nat) {
    const warn = nat.type === 'address-dependent' ? ' style="color:var(--warn)"' : '';
    const label = nat.label ? ` (${esc(nat.label)})` : '';
    html += `<br><br><b>NAT mapping:</b> <b${warn}>${esc(nat.type)}${label}</b>. ${esc(nat.detail)}`;
  }
  return { tone: evalRes.status === 'pass' ? 'pass' : 'warn', html };
}

function fillBody(card, contentHtml) {
  $('.test-body', card).innerHTML = contentHtml;
  $$('.copy-btn', card).forEach((b) => b.addEventListener('click', () => {
    navigator.clipboard.writeText(b.dataset.copy).then(() => {
      const t = b.querySelector('span'); const old = t.textContent; t.textContent = 'Copied'; setTimeout(() => (t.textContent = old), 1200);
    });
  }));
}

/* ---------------- verdict ---------------- */
function computeVerdict(results, natInfo, credProvided) {
  const ran = (k) => results[k] && results[k].ran;
  const relayOk = (k) => results[k] && results[k].eval && results[k].eval.kind === 'ok';
  const reachOk = (k) => results[k] && results[k].eval && results[k].eval.status === 'pass';
  const authFail = ['udp', 'tcp', 'tls'].some((k) => ran(k) && results[k].eval.kind === 'auth');
  const anyTurnRan = ['udp', 'tcp', 'tls'].some(ran);
  const anyRelayOk = ['udp', 'tcp', 'tls'].some(relayOk);
  const anyReachOk = ['udp', 'tcp', 'tls'].some(reachOk);

  const flowRan = ran('flow');
  const flowEval = flowRan ? results.flow.eval : null;

  // Chip order mirrors the probe order: STUN, UDP, TCP, data flow, then TLS last.
  const turnChip = (k) => {
    let s = 'skip';
    if (ran(k)) s = reachOk(k) ? 'pass' : (results[k].eval.kind === 'inconclusive' ? 'warn' : 'fail');
    return chip('TURN/' + k.toUpperCase(), s);
  };
  const chips = [];
  chips.push(chip('STUN', ran('stun') ? (reachOk('stun') ? 'pass' : 'fail') : 'skip'));
  chips.push(turnChip('udp'));
  chips.push(turnChip('tcp'));
  if (flowRan) chips.push(chip('DATA FLOW', flowEval.status === 'pass' ? 'pass' : flowEval.status === 'warn' ? 'warn' : 'fail'));
  chips.push(turnChip('tls'));
  const QUALITY_CHIP = { loss: 'LOSS', mtu: 'MTU', soak: 'SOAK', gaps: 'LIFETIME' };
  ['loss', 'mtu', 'soak', 'gaps'].forEach((k) => {
    if (ran(k)) chips.push(chip(QUALITY_CHIP[k], results[k].eval.status));
  });
  if (natInfo) chips.push(chip('NAT: ' + (natInfo.label || 'unknown'),
    natInfo.type === 'address-dependent' ? 'warn' : natInfo.type === 'endpoint-independent' ? 'pass' : 'skip'));

  // The quality probes (loss, MTU, soak, lifetime) test a relay that already
  // carries data. They cannot say "the relay works" — only that a working relay
  // degrades. So they refine a passing flow verdict rather than replacing it.
  const QUALITY_SUMMARY = {
    loss: (r) => r.eval.kind === 'lossy' ? `${r.res.lossPct}% packet loss through the relay`
      : r.eval.kind === 'degraded' ? `${r.res.lossPct}% loss / ${r.res.jitterMs} ms jitter` : null,
    mtu: (r) => r.eval.kind === 'small' ? `payloads over ${r.res.firstFail} B are dropped — below RTP size`
      : r.eval.kind === 'cliff' ? `payloads over ${r.res.firstFail} B are dropped` : null,
    soak: (r) => r.eval.kind === 'stalled' ? `traffic stalled up to ${r.res.longestStallS}s during the soak`
      : r.eval.kind === 'blips' ? `${r.res.stalls} stalled second(s) during the soak` : null,
    gaps: (r) => r.res.firstFailS != null ? `data stopped after ${r.res.firstFailS}s of silence` : null,
  };
  const qualityIssues = [];
  let qualityFail = false;
  ['loss', 'mtu', 'soak', 'gaps'].forEach((k) => {
    if (!ran(k)) return;
    const msg = QUALITY_SUMMARY[k](results[k]);
    if (!msg) return;
    qualityIssues.push(msg);
    if (results[k].eval.status === 'fail') qualityFail = true;
  });

  let status, title, text;

  // The data-flow test is the definitive signal: it proves (or disproves) that
  // the relay carries media, which allocation-only reachability can't. When it
  // ran, it dominates the verdict.
  if (flowRan && flowEval.kind === 'flow') {
    const carried = results.flow.res.perTransport.filter((r) => r.ran).map((r) => TRANSPORT_LABEL[r.key]).join(', ');
    if (qualityFail) {
      status = 'fail';
      title = 'Relay carries data but degrades';
      text = 'Every enabled transport (' + carried + ') carried data end to end, so allocation, permissions and the relay port path all work — but the relay does not hold up under scrutiny: ' + qualityIssues.join('; ') + '. A relay that allocates and then degrades is exactly what users experience as intermittent drops while reachability checks stay green.';
    } else if (qualityIssues.length) {
      status = 'warn';
      title = 'Relay verified, with warnings';
      text = 'Data traversed the relay on every enabled transport (' + carried + '), but the quality probes flagged: ' + qualityIssues.join('; ') + '. Worth re-running at different times — mild degradation on an idle test often becomes user-visible under real media load.';
    } else {
      status = 'pass';
      title = 'TURN relay verified end to end';
      text = 'Data actually traversed the relay on every enabled transport (' + carried + ') — each one probed separately, two peers forced to relay-only, bytes echoed through. Allocation, permissions and the relay port path all work. If specific clients still fail, the cause is their local network/NAT, not this server.';
    }
  } else if (flowRan && flowEval.kind === 'mixed') {
    const good = results.flow.res.perTransport.filter((r) => r.ran && r.dataOk).map((r) => TRANSPORT_LABEL[r.key]);
    const bad = results.flow.res.perTransport.filter((r) => r.ran && !r.dataOk).map((r) => TRANSPORT_LABEL[r.key]);
    status = 'warn';
    title = 'Relay carries data on some transports only';
    text = 'Data crossed the relay over ' + good.join(', ') + ' but not over ' + bad.join(', ') + '. The relay works, yet any client restricted to a failing transport cannot use it.'
      + (bad.indexOf('TLS') >= 0 ? ' TLS is among the failures — corporate and DPI-filtered networks, the exact clients that need TURNS, will fail while a combined test would have looked healthy.' : '')
      + (qualityIssues.length ? ' The quality probes also flagged: ' + qualityIssues.join('; ') + '.' : '');
  } else if (flowRan && flowEval.kind === 'noflow') {
    status = 'fail';
    title = 'Relay allocates but carries no data';
    text = 'The server accepted the allocation over the control port and handed out a relay address, but no media crossed the relay. The relay port range (coturn min-port–max-port, e.g. 49152–65535/UDP) is almost certainly not open inbound on the TURN public IP, or allowed-peer-ip denies the peer. Open the relay UDP port range and re-run. This is the failure a reachability/allocation check cannot see.';
  } else if (flowRan && flowEval.kind === 'auth') {
    status = 'fail';
    title = 'TURN credential rejected';
    text = 'The relay could not be allocated for the data-flow test — the server refused authentication (401/403). The network path is fine; fix the shared secret + TTL + suffix (or the direct username/password) and run again.';
  } else if (flowRan && flowEval.kind === 'partial') {
    status = 'warn';
    title = 'Relay connected but data was not confirmed';
    text = 'Both peers allocated a relay and ICE connected, but the DataChannel did not echo in time. This is usually a timing/MTU hiccup — re-run to confirm. If it persists, inspect the relay port range and the coturn logs.';
  } else if (flowRan && flowEval.kind === 'noalloc') {
    status = 'fail';
    title = 'Relay path could not be established';
    text = 'The data-flow test could not set up a working relay pair with the provided credential. Confirm the credential is valid and that at least one TURN transport reaches the server, then run again.';
  } else if (anyTurnRan && !credProvided) {
    const anyInconclusive = ['udp', 'tcp', 'tls'].some((k) => results[k] && results[k].eval && results[k].eval.kind === 'inconclusive');
    if (anyReachOk) {
      const reached = ['udp', 'tcp', 'tls'].filter(reachOk).map((k) => k.toUpperCase()).join(', ');
      status = 'pass';
      title = 'TURN is reachable — credentials not tested';
      text = 'The server answered the allocation request (401) over ' + reached + ', which proves this network lets you reach the TURN server on those transports — they are not blocked. The relay itself was not exercised because no credentials were provided. Add a shared secret or credential to run the data-flow test, which pushes bytes through the relay and catches a blocked relay port range that reachability alone cannot.';
    } else if (anyInconclusive) {
      status = 'warn';
      title = BROWSER_HIDES_ICE_ERRORS ? 'Reachability inconclusive in Safari' : 'Reachability inconclusive in this browser';
      text = (BROWSER_HIDES_ICE_ERRORS
        ? 'The TURN probes finished without a relay and without a visible error. Safari (and every browser on iOS/iPadOS, which all use WebKit) hides TURN authentication errors, so reachability cannot be confirmed here without credentials. '
        : 'The TURN probes finished without a relay and without a visible error, so reachability is inconclusive in this browser. ')
        + 'Add a shared secret or credential — a real relay allocation is visible in every browser' + (BROWSER_HIDES_ICE_ERRORS ? ', or re-run in Chrome or Firefox' : '') + ' for a definitive result.';
    } else {
      status = 'fail';
      title = 'TURN is unreachable on every tested transport';
      text = 'No response over the tested transports (timeouts). Likely causes: wrong host/ports, the server is down, or this network blocks all of them. Confirm the host resolves publicly and the coturn ports are open.';
    }
  } else if (anyTurnRan && !anyRelayOk && authFail) {
    status = 'fail';
    title = 'TURN credential rejected';
    text = 'The server answered but refused authentication (401/403) on every tested transport. The network path is fine — fix the credential (direct username/password, or the shared secret + TTL + suffix) and run again.';
  } else if (anyTurnRan && !anyRelayOk) {
    status = 'fail';
    title = 'TURN is unreachable on every tested transport';
    text = 'No relay could be allocated over the tested transports. Likely causes: the TURN host/ports are wrong, the server is down, or this network blocks all of them. Confirm the host resolves publicly and the coturn relay port range is open.';
  } else if (relayOk('udp')) {
    status = 'pass';
    title = 'TURN relay is healthy over UDP';
    text = 'This network reaches the TURN server and allocates a UDP relay. If clients still drop intermittently, the cause is ICE selection (the browser prefers host/srflx first) — force iceTransportPolicy: relay, or investigate ICE timing. It is not a reachability problem here.';
  } else if (relayOk('tcp')) {
    status = 'warn';
    title = 'This network blocks UDP — TURN works over TCP';
    text = 'The UDP relay failed but TCP succeeded, so your network filters UDP to the TURN port. Make sure the client offers turn:...?transport=tcp (and the coturn allows TCP). TLS/443 is the most firewall-proof upgrade if you also hit DPI.';
  } else if (relayOk('tls')) {
    status = 'warn';
    title = 'Only TLS gets through — likely deep packet inspection';
    text = 'UDP and plain TCP were blocked, but TURN over TLS succeeded. This is typical of restrictive/corporate networks. Serve TURNS on 443 and advertise turns:...:5349 (or :443) to clients so relay survives DPI.';
  } else if (ran('stun') && reachOk('stun')) {
    status = 'warn';
    title = 'STUN works, TURN was not confirmed';
    text = 'A public mapping was found via STUN, but no TURN transport was verified (none enabled or all failed). Enable the TURN probes to confirm relay reachability.';
  } else {
    status = 'fail';
    title = 'No connectivity established';
    text = 'Neither STUN nor TURN produced usable candidates. Check your network, the server hostname, and the credentials.';
  }

  const v = $('#verdict');
  v.classList.remove('is-hidden');
  v.dataset.status = status;
  $('.verdict-icon use', v).setAttribute('href', '#' + STATUS_ICON[status]);
  $('#verdictTitle').textContent = title;
  $('#verdictText').textContent = text;
  $('#verdictChips').innerHTML = chips.join('');
  return { status, title, text };
}

function chip(label, s) {
  const icon = { pass: 'i-check', fail: 'i-x', warn: 'i-alert', skip: 'i-dashed' }[s];
  return `<span class="chip" data-s="${s}"><svg class="ic" viewBox="0 0 24 24"><use href="#${icon}"/></svg>${esc(label)}</span>`;
}

/* ---------------- shareable report ---------------- */
let lastRun = null;

function buildReport(results, natInfo, cred, verdict) {
  const PROBE_LABEL = { stun: 'STUN reachability & NAT', udp: 'TURN over UDP', tcp: 'TURN over TCP', tls: 'TURN over TLS',
    flow: 'TURN relay data flow', loss: 'Relay packet loss & jitter', mtu: 'Relay payload size (MTU)',
    soak: 'Relay soak — sustained flow', gaps: 'TURN lifetime & silence gaps' };
  const resultWord = (ev) => ev.kind === 'ok' ? 'pass (relay)' : ev.kind === 'flow' ? 'pass (data)' : ev.kind === 'reachable' ? 'pass (reachable)'
    : ev.kind === 'mixed' ? 'partial (some transports)' : ev.kind === 'noflow' ? 'fail (no data)'
    : ev.kind === 'inconclusive' ? 'inconclusive' : ev.kind === 'auth' ? 'fail (401)'
    : ev.status === 'pass' ? 'pass' : ev.status === 'warn' ? 'warn' : 'fail';
  const stunRes = results.stun && results.stun.res;
  const srflxes = stunRes ? stunRes.candidates.filter((c) => c.type === 'srflx' && c.address) : [];
  const v4 = srflxes.find((c) => c.address.indexOf(':') < 0);
  const v6 = srflxes.find((c) => c.address.indexOf(':') >= 0);

  const probes = ['stun', 'udp', 'tcp', 'flow', 'tls', 'loss', 'mtu', 'soak', 'gaps'].filter((k) => results[k] && results[k].ran).map((k) => {
    const R = results[k], ev = R.eval, res = R.res;
    let detail;
    if (k === 'stun') {
      const s = res.candidates.find((c) => c.type === 'srflx');
      detail = s ? 'public ' + s.address + ':' + s.port : 'no srflx candidate';
    } else if (k === 'flow') {
      const per = res.perTransport.filter((r) => r.ran)
        .map((r) => TRANSPORT_LABEL[r.key] + '=' + (r.dataOk ? 'data ok' + (r.ms != null ? ' ' + r.ms + 'ms' : '') : (r.connected ? 'no echo' : 'no relay')));
      detail = per.length ? per.join(', ') : 'no transport enabled';
    } else if (k === 'loss') {
      detail = res.setupFailed ? 'relay pair could not be established'
        : res.received ? res.lossPct + '% loss (' + res.received + '/' + res.sent + '), jitter ' + res.jitterMs + ' ms, RTT ' + res.minMs + '/' + res.avgMs + '/' + res.maxMs + ' ms'
        : 'no packets returned (' + res.sent + ' sent)';
    } else if (k === 'mtu') {
      detail = res.setupFailed ? 'relay pair could not be established'
        : res.largestOk ? 'largest payload through relay ' + res.largestOk + ' B' + (res.firstFail != null ? ', dropped from ' + res.firstFail + ' B' : ', no cliff up to ' + MTU_SIZES[MTU_SIZES.length - 1] + ' B')
        : 'not even the smallest payload crossed';
    } else if (k === 'soak') {
      detail = res.setupFailed ? 'relay pair could not be established'
        : res.seconds + 's soak, ' + res.pongs + '/' + res.pings + ' echoes, ' + res.stalls + ' stalled second(s), longest stall ' + res.longestStallS + 's';
    } else if (k === 'gaps') {
      detail = res.setupFailed ? 'relay pair could not be established'
        : res.firstFailS != null ? 'data stopped after ' + res.firstFailS + 's of silence'
        : 'survived silence up to ' + (res.marks.length ? res.marks[res.marks.length - 1].seconds : 0) + 's';
    } else if (ev.kind === 'ok') {
      const relay = res.candidates.find((c) => c.type === 'relay');
      detail = relay ? 'relay ' + relay.address + ':' + relay.port : 'relay allocated';
    } else if (ev.kind === 'reachable') {
      detail = 'answered 401 (no credentials provided)';
    } else if (ev.kind === 'inconclusive') {
      detail = 'no relay, no visible error (browser may hide TURN errors)';
    } else if (ev.kind === 'auth') {
      detail = 'credential rejected (401/403)';
    } else {
      detail = res.timedOut ? 'timed out / no response' : 'no relay allocated';
    }
    return { probe: k, label: PROBE_LABEL[k], url: k === 'stun' ? state.stun : turnUrl(k),
      result: resultWord(ev), status: ev.status, kind: ev.kind,
      ms: res.firstMs != null ? res.firstMs : res.gatherMs, detail: detail };
  });

  return {
    tool: 'TURN Doctor',
    at: new Date().toISOString(),
    reference: val('reference').trim() || null,
    server: { host: state.host, udpTcpPort: Number(state.port), tlsPort: Number(state.tlsPort), stun: state.stun || null },
    auth: { mode: state.authMode, credentialsProvided: cred.provided },
    client: {
      publicIPv4: v4 ? v4.address : null,
      publicIPv6: v6 ? v6.address : null,
      nat: natInfo ? { type: natInfo.type, label: natInfo.label || null } : null,
      userAgent: navigator.userAgent,
    },
    verdict: verdict,
    probes: probes,
  };
}

function reportMarkdown(r) {
  const L = [];
  L.push('### TURN Doctor report');
  L.push('');
  if (r.reference) L.push('- **Reference:** ' + r.reference);
  L.push('- **When:** ' + r.at);
  L.push('- **TURN host:** `' + r.server.host + '` — UDP/TCP ' + r.server.udpTcpPort + ', TLS ' + r.server.tlsPort);
  L.push('- **STUN:** `' + (r.server.stun || '—') + '`');
  L.push('- **Credentials:** ' + (r.auth.credentialsProvided ? r.auth.mode + ' (provided)' : 'none — reachability only'));
  L.push('');
  L.push('**Client environment**');
  L.push('- Public IP: ' + (r.client.publicIPv4 || '—') + (r.client.publicIPv6 ? '  |  ' + r.client.publicIPv6 : ''));
  L.push('- NAT: ' + (r.client.nat ? r.client.nat.type + (r.client.nat.label ? ' (' + r.client.nat.label + ')' : '') : '—'));
  L.push('- Browser: ' + r.client.userAgent);
  L.push('');
  L.push('**Verdict — ' + r.verdict.title + '**  _(' + r.verdict.status + ')_');
  L.push('');
  L.push('> ' + r.verdict.text);
  L.push('');
  L.push('| Probe | Result | Time | Detail |');
  L.push('|---|---|---|---|');
  r.probes.forEach((p) => L.push('| ' + p.label + ' | ' + p.result + ' | ' + (p.ms != null ? p.ms + ' ms' : '—') + ' | ' + p.detail + ' |'));
  L.push('');
  L.push('_Generated by TURN Doctor · ' + (location.origin + location.pathname) + '_');
  return L.join('\n');
}

function shareFeedback(msg) {
  const span = $('#shareBtn span');
  const old = span.dataset.label || span.textContent;
  span.dataset.label = old;
  span.textContent = msg;
  setTimeout(() => { span.textContent = span.dataset.label; }, 1400);
}
function downloadText(text, filename, mime) {
  const blob = new Blob([text], { type: mime || 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 100);
}

/* ---------------- loading splash ---------------- */
let diagT0 = 0;
function splashShow() {
  diagT0 = performance.now();
  $('#loadingLog').innerHTML = '';
  $('#loadingBarFill').style.width = '0%';
  $('#loadingOverlay').classList.remove('is-hidden', 'is-closing');
}
function splashHide() {
  const o = $('#loadingOverlay');
  o.classList.add('is-closing');
  setTimeout(() => { o.classList.add('is-hidden'); o.classList.remove('is-closing'); }, 300);
}
function splashCurrent(msg) { $('#loadingCurrent').textContent = msg; }
function splashProgress(done, total) {
  $('#loadingCount').textContent = done + '/' + total;
  $('#loadingBarFill').style.width = (total ? Math.round((done / total) * 100) : 0) + '%';
}
function diagLog(msg, kind) {
  const el = $('#loadingLog');
  const t = ((performance.now() - diagT0) / 1000).toFixed(1);
  const line = document.createElement('div');
  line.className = 'lg';
  line.innerHTML = '<span class="lg-t">' + t + 's</span><span class="lg-' + (kind || 'dim') + '">' + esc(msg) + '</span>';
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

/* ---------------- orchestration ---------------- */
const state = { authMode: 'secret', host: '', port: 3478, tlsPort: 5349, stun: '', running: false,
                soakSeconds: DEFAULT_SOAK_SECONDS, gapMarks: DEFAULT_GAP_MARKS };

function val(id) { return $('#' + id).value; }

function readConfig() {
  state.host = val('turnHost').trim();
  state.port = val('turnPort').trim() || '3478';
  state.tlsPort = val('tlsPort').trim() || '5349';
  state.stun = val('stunServer').trim();
  const soak = parseInt(val('soakSeconds'), 10);
  state.soakSeconds = Number.isFinite(soak) && soak > 0 ? Math.min(soak, 900) : DEFAULT_SOAK_SECONDS;
  const marks = parseGapMarks(val('gapMarks'));
  state.gapMarks = marks.length ? marks.join(',') : DEFAULT_GAP_MARKS;
}

function validate() {
  const bad = [];
  if (!state.host) bad.push('turnHost');
  bad.forEach((id) => {
    const el = $('#' + id);
    el.style.borderColor = 'var(--fail)';
    el.addEventListener('input', () => (el.style.borderColor = ''), { once: true });
  });
  if (bad.length) { $('#' + bad[0]).focus(); return false; }
  return true;
}

async function run() {
  if (state.running) return;
  readConfig();
  if (!validate()) return;

  state.running = true;
  const btn = $('#runBtn');
  btn.disabled = true;
  $('span', btn).textContent = 'Running';
  $('#empty').classList.add('is-hidden');
  saveConfig();

  splashShow();
  splashCurrent('Preparing credentials');
  diagLog('Starting diagnostics — forcing iceTransportPolicy: relay per transport', 'run');

  let cred;
  try {
    cred = await resolveCredential();
    if (cred.provided) diagLog('Credential ready — username ' + cred.username, 'ok');
    else diagLog('No credentials provided — testing TURN reachability only (a 401 still proves the server is reachable)', 'dim');
  } catch (e) {
    splashHide();
    state.running = false;
    btn.disabled = false;
    $('span', btn).textContent = 'Run diagnostics';
    $('#empty').classList.remove('is-hidden');
    $('#empty').innerHTML = '<svg class="ic ic-xl" viewBox="0 0 24 24"><use href="#i-lock"/></svg><h3>HTTPS required</h3><p>' + esc(e.message) + '</p>';
    return;
  }

  const enabled = {
    stun: $('#testStun').checked && !!state.stun,
    udp: $('#testUdp').checked,
    tcp: $('#testTcp').checked,
    tls: $('#testTls').checked,
    flow: $('#testFlow').checked,
    loss: $('#testLoss').checked,
    mtu: $('#testMtu').checked,
    soak: $('#testSoak').checked,
    gaps: $('#testGaps').checked,
  };
  const anyTransport = enabled.udp || enabled.tcp || enabled.tls;
  const probeName = (k) => (TEST_DEFS.find((t) => t.key === k) || {}).name || k;
  // Every data probe needs a credential (no allocation without auth) and at
  // least one TURN transport enabled to carry it.
  DATA_PROBES.forEach((k) => {
    if (!enabled[k]) return;
    if (!cred.provided) diagLog(probeName(k) + ' — skipped (needs a credential to allocate a relay and push bytes through it)', 'warn');
    else if (!anyTransport) diagLog(probeName(k) + ' — skipped (enable at least one TURN transport to carry it)', 'warn');
  });
  const defs = TEST_DEFS.filter((d) => {
    if (DATA_PROBES.indexOf(d.key) >= 0) return enabled[d.key] && cred.provided && anyTransport;
    return enabled[d.key];
  }).map((d) => ({ ...d, url: turnUrl(d.key) }));
  renderCards(defs);
  splashProgress(0, defs.length);

  const results = {};
  let natInfo = null;
  let done = 0;

  for (const d of defs) {
    const card = $(`.test[data-key="${d.key}"]`);
    setStatus(card, 'running');
    $('.test-time', card).textContent = '…';
    splashCurrent(d.name);

    let res, evalRes, explain;
    if (d.key === 'stun') {
      diagLog('STUN — gathering candidates via ' + state.stun, 'run');
      res = await probe({ iceServers: [{ urls: state.stun }], policy: 'all', want: 'srflx' });
      const srflx = res.candidates.find((c) => c.type === 'srflx');
      if (srflx) {
        diagLog('STUN — public mapping ' + srflx.address + ':' + srflx.port + ' (' + res.firstMs + ' ms)', 'ok');
        splashCurrent('Detecting NAT mapping');
        diagLog('NAT — comparing mappings across a second STUN server', 'run');
        natInfo = await detectNat(srflx);
        if (natInfo) diagLog('NAT — ' + natInfo.type + (natInfo.label ? ' (' + natInfo.label + ')' : ''), natInfo.type === 'address-dependent' ? 'warn' : 'ok');
      } else {
        diagLog('STUN — no reflexive candidate discovered', 'no');
      }
      evalRes = { status: srflx ? 'pass' : 'warn', kind: srflx ? 'ok' : 'nostun' };
      explain = explainStun(evalRes, res, natInfo);
    } else if (d.key === 'flow') {
      diagLog('Relay data-flow — probing each transport separately so UDP cannot mask TCP/TLS', 'run');
      res = await flowProbe({ enabled, cred });
      res.perTransport.filter((r) => r.ran).forEach((r) => {
        if (r.dataOk) diagLog('  ' + TRANSPORT_LABEL[r.key] + ' — data crossed the relay ' + r.aRelay + ' ↔ ' + r.bRelay + ' (' + r.ms + ' ms)', 'ok');
        else if (r.connected) diagLog('  ' + TRANSPORT_LABEL[r.key] + ' — relay allocated but NO data crossed (relay port range / peer ACL)', 'no');
        else diagLog('  ' + TRANSPORT_LABEL[r.key] + ' — no relay allocated' + (r.timedOut ? ' (timed out)' : ''), 'no');
      });
      evalRes = evaluateFlow(res);
      explain = explainFlow(evalRes, res);
    } else if (d.key === 'loss') {
      diagLog('Loss & jitter — ' + LOSS_PINGS + ' packets over an unreliable DataChannel (SCTP retransmission off)', 'run');
      res = await lossProbe({ iceServers: flowIceServers(enabled, cred) });
      evalRes = evaluateLoss(res);
      if (res.setupFailed) diagLog('Loss & jitter — relay pair could not be established', 'no');
      else if (!res.received) diagLog('Loss & jitter — NOT ONE of ' + res.sent + ' packets returned', 'no');
      else diagLog('Loss & jitter — ' + res.lossPct + '% loss (' + res.received + '/' + res.sent + '), jitter ' + res.jitterMs + ' ms, RTT avg ' + res.avgMs + ' ms',
        evalRes.status === 'pass' ? 'ok' : evalRes.status === 'warn' ? 'warn' : 'no');
      explain = explainLoss(evalRes, res);
    } else if (d.key === 'mtu') {
      diagLog('Payload size — walking ' + MTU_SIZES[0] + '→' + MTU_SIZES[MTU_SIZES.length - 1] + ' B through the relay to find a cliff', 'run');
      res = await mtuProbe({ iceServers: flowIceServers(enabled, cred) });
      evalRes = evaluateMtu(res);
      if (res.setupFailed) diagLog('Payload size — relay pair could not be established', 'no');
      else if (res.firstFail != null) diagLog('Payload size — largest through relay ' + res.largestOk + ' B, dropped from ' + res.firstFail + ' B',
        evalRes.status === 'fail' ? 'no' : 'warn');
      else diagLog('Payload size — no cliff up to ' + res.largestOk + ' B', 'ok');
      explain = explainMtu(evalRes, res);
    } else if (d.key === 'soak') {
      diagLog('Soak — holding the relay open for ' + state.soakSeconds + 's and sampling getStats every second', 'run');
      res = await soakProbe({
        iceServers: flowIceServers(enabled, cred), seconds: state.soakSeconds,
        onTick: (tick, total) => {
          splashCurrent(d.name + ' — ' + tick.t + '/' + total + 's');
          if (!tick.echoed) diagLog('  soak t=' + tick.t + 's — no echo this second', 'no');
        },
      });
      evalRes = evaluateSoak(res);
      if (res.setupFailed) diagLog('Soak — relay pair could not be established', 'no');
      else diagLog('Soak — ' + res.pongs + '/' + res.pings + ' echoes, ' + res.stalls + ' stalled second(s), longest stall ' + res.longestStallS + 's',
        evalRes.status === 'pass' ? 'ok' : evalRes.status === 'warn' ? 'warn' : 'no');
      explain = explainSoak(evalRes, res);
    } else if (d.key === 'gaps') {
      const marks = parseGapMarks(state.gapMarks);
      diagLog('Lifetime — testing silences of ' + marks.join('s, ') + 's against TURN permission (300s) and allocation (600s) lifetimes', 'run');
      res = await gapsProbe({
        iceServers: flowIceServers(enabled, cred), marks,
        onMark: (m) => {
          if (m.pending) { splashCurrent(d.name + ' — waiting ' + m.seconds + 's in silence'); diagLog('  going silent for ' + m.seconds + 's…', 'dim'); return; }
          if (m.seconds === 0) diagLog('  baseline echo ' + (m.ok ? m.ms + ' ms' : 'FAILED'), m.ok ? 'ok' : 'no');
          else diagLog('  after ' + m.seconds + 's silence — ' + (m.ok ? 'echo ok (' + m.ms + ' ms)' : 'NO ECHO'), m.ok ? 'ok' : 'no');
        },
      });
      evalRes = evaluateGaps(res);
      explain = explainGaps(evalRes, res);
    } else {
      diagLog(d.name + (cred.provided ? ' — allocating relay via ' : ' — probing reachability via ') + turnUrl(d.key), 'run');
      const iceServers = [{ urls: turnUrl(d.key), username: cred.username, credential: cred.password }];
      res = await probe({ iceServers, policy: 'relay', want: 'relay' });
      evalRes = evaluateTurn(res, cred.provided);
      if (evalRes.kind === 'ok') {
        const relay = res.candidates.find((c) => c.type === 'relay');
        diagLog(d.name + ' — relay ' + (relay ? relay.address + ':' + relay.port : 'allocated') + ' (' + res.firstMs + ' ms)', 'ok');
      } else if (evalRes.kind === 'reachable') {
        diagLog(d.name + ' — reachable (401 — no credentials provided)', 'ok');
      } else if (evalRes.kind === 'auth') {
        diagLog(d.name + ' — credential rejected (401/403)', 'no');
      } else if (evalRes.kind === 'inconclusive') {
        diagLog(d.name + ' — inconclusive (no relay, no visible error — browser may hide TURN errors)', 'warn');
      } else {
        diagLog(d.name + ' — no response' + (res.timedOut ? ' (timed out)' : ''), 'no');
      }
      explain = explainTurn(d.key, evalRes, res);
    }

    results[d.key] = { ran: true, eval: evalRes, res };
    const ms = res.firstMs != null ? res.firstMs : res.gatherMs;
    $('.test-time', card).textContent = (ms != null ? ms + ' ms' : '—');
    setStatus(card, evalRes.status);
    done++;
    splashProgress(done, defs.length);

    const credLine = (d.key !== 'stun' && cred.provided) ? `
      <p class="data-title">Credential used</p>
      <div style="margin-bottom:14px">
        <button class="copy-btn" data-copy="${esc(cred.username)}"><svg class="ic" viewBox="0 0 24 24"><use href="#i-copy"/></svg><span>username</span></button>
        <button class="copy-btn" data-copy="${esc(cred.password)}" style="margin-left:6px"><svg class="ic" viewBox="0 0 24 24"><use href="#i-copy"/></svg><span>password</span></button>
      </div>` : '';

    fillBody(card, `
      <div class="test-explain tone-${explain.tone}">${explain.html}</div>
      <p class="data-title">ICE candidates (${res.candidates.length})</p>
      <table class="cand-table"><thead><tr><th>Type</th><th>Proto</th><th>Address</th><th>Port</th></tr></thead>
      <tbody>${candRows(res.candidates)}</tbody></table>
      ${errRows(res.errors, evalRes.status === 'pass')}
      ${credLine}`);
  }

  splashCurrent('Computing verdict');
  diagLog('All probes complete — computing verdict', 'run');
  const verdict = computeVerdict(results, natInfo, cred.provided);
  lastRun = buildReport(results, natInfo, cred, verdict);
  diagLog('Done', 'ok');

  await new Promise((r) => setTimeout(r, 600));
  splashHide();
  setTimeout(() => { $('#verdict').scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 340);

  state.running = false;
  btn.disabled = false;
  $('span', btn).textContent = 'Run diagnostics';
}

/* ---------------- persistence (no secrets) ---------------- */
const SAVE_KEYS = ['turnHost', 'turnPort', 'tlsPort', 'stunServer', 'ttl', 'suffix', 'username', 'soakSeconds', 'gapMarks'];
function saveConfig() {
  const o = { authMode: state.authMode };
  SAVE_KEYS.forEach((k) => (o[k] = val(k)));
  try { localStorage.setItem('turn-doctor.cfg', JSON.stringify(o)); } catch (e) {}
}
function loadConfig() {
  let o; try { o = JSON.parse(localStorage.getItem('turn-doctor.cfg')); } catch (e) { return; }
  if (!o) return;
  SAVE_KEYS.forEach((k) => { if (o[k] != null && $('#' + k)) $('#' + k).value = o[k]; });
  if (o.authMode) setAuthMode(o.authMode);
}

// True if any advanced field holds a non-default / non-empty value worth revealing.
function hasAdvancedValues() {
  const filled = (id) => val(id).trim() !== '';
  const nonDefault = (id, def) => { const v = val(id).trim(); return v !== '' && v !== def; };
  return nonDefault('turnPort', '3478') || nonDefault('tlsPort', '5349')
    || nonDefault('stunServer', 'stun:stun.l.google.com:19302') || nonDefault('ttl', '3600')
    || nonDefault('soakSeconds', String(DEFAULT_SOAK_SECONDS)) || nonDefault('gapMarks', DEFAULT_GAP_MARKS)
    || filled('sharedSecret') || filled('username') || filled('password')
    || filled('suffix') || filled('reference')
    || state.authMode === 'direct'
    || !$('#testStun').checked || !$('#testUdp').checked || !$('#testTcp').checked || $('#testTls').checked || !$('#testFlow').checked
    || !$('#testLoss').checked || !$('#testMtu').checked || $('#testSoak').checked || $('#testGaps').checked;
}

/* ---------------- UI wiring ---------------- */
function setAuthMode(mode) {
  state.authMode = mode;
  $$('.seg').forEach((s) => {
    const on = s.dataset.auth === mode;
    s.classList.toggle('is-active', on);
    s.setAttribute('aria-selected', String(on));
  });
  $$('.auth-pane').forEach((p) => p.classList.toggle('is-hidden', p.dataset.pane !== mode));
}

function init() {
  $$('.seg').forEach((s) => s.addEventListener('click', () => setAuthMode(s.dataset.auth)));
  $$('.affix-btn').forEach((b) => b.addEventListener('click', () => {
    const inp = $('#' + b.dataset.reveal);
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    b.classList.toggle('is-on', show);
  }));
  $('#cfgForm').addEventListener('submit', (e) => { e.preventDefault(); run(); });
  $('#resetBtn').addEventListener('click', () => {
    try { localStorage.removeItem('turn-doctor.cfg'); } catch (e) {}
    location.reload();
  });

  const shareBtn = $('#shareBtn'), shareMenu = $('#shareMenu'), shareWrap = $('.share');
  if (shareBtn) {
    shareBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const hidden = shareMenu.classList.toggle('is-hidden');
      shareWrap.classList.toggle('is-open', !hidden);
      shareBtn.setAttribute('aria-expanded', String(!hidden));
    });
    shareMenu.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-share]');
      if (!b || !lastRun) return;
      const kind = b.dataset.share;
      if (kind === 'md') navigator.clipboard.writeText(reportMarkdown(lastRun)).then(() => shareFeedback('Markdown copied'));
      else if (kind === 'json') navigator.clipboard.writeText(JSON.stringify(lastRun, null, 2)).then(() => shareFeedback('JSON copied'));
      else if (kind === 'download') downloadText(reportMarkdown(lastRun), 'turn-doctor-' + lastRun.at.replace(/[:.]/g, '-') + '.md', 'text/markdown');
      shareMenu.classList.add('is-hidden'); shareWrap.classList.remove('is-open'); shareBtn.setAttribute('aria-expanded', 'false');
    });
    document.addEventListener('click', () => { shareMenu.classList.add('is-hidden'); shareWrap.classList.remove('is-open'); shareBtn.setAttribute('aria-expanded', 'false'); });
  }

  const advToggle = $('#advToggle'), advanced = $('#advanced');
  const setAdvanced = (open) => {
    advanced.classList.toggle('is-collapsed', !open);
    advToggle.setAttribute('aria-expanded', String(open));
  };
  if (advToggle) advToggle.addEventListener('click', () => setAdvanced(advanced.classList.contains('is-collapsed')));

  loadConfig();
  if (hasAdvancedValues()) setAdvanced(true);

  if (!window.RTCPeerConnection) {
    $('#empty').innerHTML = '<h3>WebRTC unavailable</h3><p>This browser does not expose RTCPeerConnection, so ICE probing cannot run.</p>';
  }
}

document.addEventListener('DOMContentLoaded', init);
