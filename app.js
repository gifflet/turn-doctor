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
  { key: 'tls', name: 'TURN over TLS', want: 'relay' },
  { key: 'flow', name: 'TURN relay data flow', want: 'data' },
];

const NAT_FALLBACK_STUN = ['stun:stun.cloudflare.com:3478', 'stun:stun1.l.google.com:19302'];
const PROBE_TIMEOUT = 9000;

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

/* ---------------- relay data-flow probe ----------------
   Allocating a relay candidate only proves the server answered the Allocate
   over the control port (3478) — the relay address is minted from that reply
   before any byte crosses the relay port range. To prove the relay actually
   carries media, stand up two PeerConnections in this browser, force BOTH to
   iceTransportPolicy: 'relay', wire them together, and echo a DataChannel
   message through the relay. Bytes returning = the relay path (allocation +
   permission + channel-bind + relay port range) genuinely works. */
function relayFlowProbe({ iceServers, timeout = 12000 }) {
  return new Promise((resolve) => {
    const res = { dataOk: false, connected: false, aRelay: null, bRelay: null, errors: [], candidates: [], firstMs: null, gatherMs: null, timedOut: false };
    const t0 = performance.now();
    let a, b, dc, to, done = false;
    const finish = () => {
      if (done) return;
      done = true;
      res.gatherMs = Math.round(performance.now() - t0);
      clearTimeout(to);
      try { a && a.close(); } catch (e) {}
      try { b && b.close(); } catch (e) {}
      resolve(res);
    };
    try {
      a = new RTCPeerConnection({ iceServers, iceTransportPolicy: 'relay' });
      b = new RTCPeerConnection({ iceServers, iceTransportPolicy: 'relay' });
    } catch (e) {
      res.errors.push({ errorText: 'PeerConnection init failed: ' + e.message });
      resolve(res);
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
          if (side === 'a' && !res.aRelay) res.aRelay = c.address + ':' + c.port;
          if (side === 'b' && !res.bRelay) res.bRelay = c.address + ':' + c.port;
          res.candidates.push({ type: c.type, protocol: c.protocol, address: c.address, port: c.port });
        }
        if (ready[side === 'a' ? 'b' : 'a']) peerFor[side]().addIceCandidate(c).catch(() => {});
        else queue[side].push(c);
      };
      pc.onicecandidateerror = (e) => { if (e.errorCode) res.errors.push({ url: e.url, errorCode: e.errorCode, errorText: e.errorText }); };
      pc.onconnectionstatechange = () => { if (pc.connectionState === 'connected') res.connected = true; };
    };
    wire(a, 'a');
    wire(b, 'b');

    dc = a.createDataChannel('turndoctor-flow');
    dc.onopen = () => { try { dc.send('ping'); } catch (e) {} };
    dc.onmessage = (m) => { if (m.data === 'pong') { res.firstMs = Math.round(performance.now() - t0); res.dataOk = true; finish(); } };
    b.ondatachannel = (e) => { const ch = e.channel; ch.onmessage = (m) => { if (m.data === 'ping') { try { ch.send('pong'); } catch (e2) {} } }; };

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
        res.errors.push({ errorText: 'negotiation failed: ' + e.message });
        finish();
      }
    })();

    to = setTimeout(() => { res.timedOut = true; finish(); }, timeout);
  });
}

function evaluateFlow(res) {
  if (res.dataOk) return { status: 'pass', kind: 'flow' };
  const authErr = res.errors.some((e) => { const c = Number(e.errorCode); return c === 401 || c === 403; });
  if (res.aRelay && res.bRelay) {
    // Both allocations succeeded (relay addresses handed out) but no byte crossed:
    // the relay port path is broken (firewall on the port range, or peer ACL).
    return res.connected ? { status: 'warn', kind: 'partial' } : { status: 'fail', kind: 'noflow' };
  }
  if (authErr) return { status: 'fail', kind: 'auth' };
  return { status: 'fail', kind: 'noalloc' };
}

function explainFlow(evalRes, res) {
  if (evalRes.kind === 'flow') {
    return { tone: 'pass', html: `Data crossed the relay <b>end to end</b> in ${res.firstMs} ms. Two peers were forced to <code>iceTransportPolicy: relay</code>, both allocated a relay (<b class="mono">${esc(res.aRelay)}</b> ↔ <b class="mono">${esc(res.bRelay)}</b>), ICE connected, and a <code>DataChannel</code> echoed a message <b>through the relay</b>. This proves the relay actually carries media — not just that an allocation address was handed out.` };
  }
  if (evalRes.kind === 'noflow') {
    return { tone: 'fail', html: `Both peers <b>allocated a relay</b> (<b class="mono">${esc(res.aRelay)}</b>, <b class="mono">${esc(res.bRelay)}</b>) but <b>no data crossed it</b>${res.timedOut ? ' (timed out)' : ''}. The allocation succeeds over the control port, yet media can't flow through the relay port. Classic causes: the coturn relay port range (<code>min-port</code>–<code>max-port</code>, e.g. <code>49152–65535/UDP</code>) isn't open inbound on the TURN public IP, or <code>allowed-peer-ip</code> denies the peer. <b>This is exactly the failure an allocation-only check cannot see.</b>` };
  }
  if (evalRes.kind === 'partial') {
    return { tone: 'warn', html: `Both relays were allocated and ICE reported <code>connected</code>, but the <code>DataChannel</code> didn't echo in time. Likely a timing/MTU hiccup on the relay path — re-run; if it persists, inspect the relay port range and the coturn logs.` };
  }
  if (evalRes.kind === 'auth') {
    return { tone: 'fail', html: `The relay couldn't be allocated for the data-flow test because the <b>credential was rejected</b> (401/403). Fix the shared secret / TTL / username-password, then re-run.` };
  }
  return { tone: 'fail', html: `No relay could be allocated for the data-flow test${res.timedOut ? ' (timed out)' : ''}. If the per-transport probes passed but this didn't, the server minted an allocation address but the relay itself isn't usable from here.` };
}

/* ---------------- per-transport url builders ---------------- */
function turnUrl(key) {
  const host = state.host, port = state.port, tls = state.tlsPort;
  if (key === 'udp') return `turn:${host}:${port}?transport=udp`;
  if (key === 'tcp') return `turn:${host}:${port}?transport=tcp`;
  if (key === 'tls') return `turns:${host}:${tls}?transport=tcp`;
  if (key === 'flow') return `relay ↔ relay · turn:${host}`;
  return state.stun;
}

// iceServers for the data-flow test: every enabled TURN transport with the
// resolved credential, mirroring what a real client would offer.
function flowIceServers(enabled, cred) {
  const urls = ['udp', 'tcp', 'tls'].filter((k) => enabled[k]).map((k) => turnUrl(k));
  return [{ urls, username: cred.username, credential: cred.password }];
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

  const chips = [];
  chips.push(chip('STUN', ran('stun') ? (reachOk('stun') ? 'pass' : 'fail') : 'skip'));
  ['udp', 'tcp', 'tls'].forEach((k) => {
    let s = 'skip';
    if (ran(k)) s = reachOk(k) ? 'pass' : (results[k].eval.kind === 'inconclusive' ? 'warn' : 'fail');
    chips.push(chip('TURN/' + k.toUpperCase(), s));
  });
  if (flowRan) chips.push(chip('DATA FLOW', flowEval.status === 'pass' ? 'pass' : flowEval.status === 'warn' ? 'warn' : 'fail'));
  if (natInfo) chips.push(chip('NAT: ' + (natInfo.label || 'unknown'),
    natInfo.type === 'address-dependent' ? 'warn' : natInfo.type === 'endpoint-independent' ? 'pass' : 'skip'));

  let status, title, text;

  // The data-flow test is the definitive signal: it proves (or disproves) that
  // the relay carries media, which allocation-only reachability can't. When it
  // ran, it dominates the verdict.
  if (flowRan && flowEval.kind === 'flow') {
    status = 'pass';
    title = 'TURN relay verified end to end';
    text = 'Data actually traversed the relay — two peers were forced to relay-only and a DataChannel echoed through it. Allocation, permissions and the relay port path all work. If specific clients still fail, the cause is their local network/NAT, not this server.';
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
    title = 'Relay could not be allocated';
    text = 'The data-flow test could not allocate a relay with the provided credential. Confirm the credential is valid and that at least one TURN transport reaches the server, then run again.';
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
  const PROBE_LABEL = { stun: 'STUN reachability & NAT', udp: 'TURN over UDP', tcp: 'TURN over TCP', tls: 'TURN over TLS', flow: 'TURN relay data flow' };
  const resultWord = (ev) => ev.kind === 'ok' ? 'pass (relay)' : ev.kind === 'flow' ? 'pass (data)' : ev.kind === 'reachable' ? 'pass (reachable)'
    : ev.kind === 'noflow' ? 'fail (no data)' : ev.kind === 'inconclusive' ? 'inconclusive' : ev.kind === 'auth' ? 'fail (401)'
    : ev.status === 'pass' ? 'pass' : ev.status === 'warn' ? 'warn' : 'fail';
  const stunRes = results.stun && results.stun.res;
  const srflxes = stunRes ? stunRes.candidates.filter((c) => c.type === 'srflx' && c.address) : [];
  const v4 = srflxes.find((c) => c.address.indexOf(':') < 0);
  const v6 = srflxes.find((c) => c.address.indexOf(':') >= 0);

  const probes = ['stun', 'udp', 'tcp', 'tls', 'flow'].filter((k) => results[k] && results[k].ran).map((k) => {
    const R = results[k], ev = R.eval, res = R.res;
    let detail;
    if (k === 'stun') {
      const s = res.candidates.find((c) => c.type === 'srflx');
      detail = s ? 'public ' + s.address + ':' + s.port : 'no srflx candidate';
    } else if (k === 'flow') {
      if (ev.kind === 'flow') detail = 'data echoed through relay ' + res.aRelay + ' ↔ ' + res.bRelay + ' (' + res.firstMs + ' ms)';
      else if (ev.kind === 'noflow') detail = 'relay allocated (' + res.aRelay + ', ' + res.bRelay + ') but no data traversed';
      else if (ev.kind === 'partial') detail = 'connected but DataChannel did not echo';
      else if (ev.kind === 'auth') detail = 'credential rejected (401/403)';
      else detail = res.timedOut ? 'no relay / timed out' : 'no relay allocated';
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
const state = { authMode: 'secret', host: '', port: 3478, tlsPort: 5349, stun: '', running: false };

function val(id) { return $('#' + id).value; }

function readConfig() {
  state.host = val('turnHost').trim();
  state.port = val('turnPort').trim() || '3478';
  state.tlsPort = val('tlsPort').trim() || '5349';
  state.stun = val('stunServer').trim();
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
  };
  if (enabled.flow && !cred.provided) {
    diagLog('Relay data-flow — skipped (needs a credential to allocate a relay and push bytes through it)', 'warn');
  }
  // The data-flow test needs a credential (no allocation without auth) and at
  // least one TURN transport enabled to carry it.
  const defs = TEST_DEFS.filter((d) => {
    if (d.key === 'flow') return enabled.flow && cred.provided && (enabled.udp || enabled.tcp || enabled.tls);
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
      diagLog('Relay data-flow — forcing two peers through the relay and echoing a DataChannel', 'run');
      res = await relayFlowProbe({ iceServers: flowIceServers(enabled, cred) });
      evalRes = evaluateFlow(res);
      if (evalRes.kind === 'flow') {
        diagLog('Relay data-flow — bytes crossed the relay ' + res.aRelay + ' ↔ ' + res.bRelay + ' (' + res.firstMs + ' ms)', 'ok');
      } else if (evalRes.kind === 'noflow') {
        diagLog('Relay data-flow — relay allocated but NO data crossed (relay port range / peer ACL blocked)', 'no');
      } else if (evalRes.kind === 'partial') {
        diagLog('Relay data-flow — connected but DataChannel did not echo in time', 'warn');
      } else if (evalRes.kind === 'auth') {
        diagLog('Relay data-flow — credential rejected (401/403)', 'no');
      } else {
        diagLog('Relay data-flow — no relay allocated' + (res.timedOut ? ' (timed out)' : ''), 'no');
      }
      explain = explainFlow(evalRes, res);
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
const SAVE_KEYS = ['turnHost', 'turnPort', 'tlsPort', 'stunServer', 'ttl', 'suffix', 'username'];
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
    || filled('sharedSecret') || filled('username') || filled('password')
    || filled('suffix') || filled('reference')
    || state.authMode === 'direct'
    || !$('#testStun').checked || !$('#testUdp').checked || !$('#testTcp').checked || $('#testTls').checked || !$('#testFlow').checked;
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
