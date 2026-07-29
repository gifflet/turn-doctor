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
];

const NAT_FALLBACK_STUN = ['stun:stun.cloudflare.com:3478', 'stun:stun1.l.google.com:19302'];
const PROBE_TIMEOUT = 9000;

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

/* ---------------- per-transport url builders ---------------- */
function turnUrl(key) {
  const host = state.host, port = state.port, tls = state.tlsPort;
  if (key === 'udp') return `turn:${host}:${port}?transport=udp`;
  if (key === 'tcp') return `turn:${host}:${port}?transport=tcp`;
  if (key === 'tls') return `turns:${host}:${tls}?transport=tcp`;
  return state.stun;
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
  if (has(701) || res.timedOut || res.candidates.length === 0) return { status: 'fail', kind: 'unreach' };
  return { status: 'fail', kind: 'unreach' };
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

function errRows(errs) {
  const meaningful = errs.filter((e) => e.errorCode || e.errorText);
  if (!meaningful.length) return '';
  const label = (e) => {
    const c = Number(e.errorCode);
    if (c === 401) return 'Unauthorized — credential rejected';
    if (c === 403) return 'Forbidden — peer/permission denied';
    if (c === 438) return 'Stale nonce';
    if (c === 701) return 'Server not reachable (STUN/TURN allocate failed)';
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

  const chips = [];
  chips.push(chip('STUN', ran('stun') ? (reachOk('stun') ? 'pass' : 'fail') : 'skip'));
  ['udp', 'tcp', 'tls'].forEach((k) => chips.push(chip('TURN/' + k.toUpperCase(), ran(k) ? (reachOk(k) ? 'pass' : 'fail') : 'skip')));
  if (natInfo) chips.push(chip('NAT: ' + (natInfo.label || 'unknown'),
    natInfo.type === 'address-dependent' ? 'warn' : natInfo.type === 'endpoint-independent' ? 'pass' : 'skip'));

  let status, title, text;

  if (anyTurnRan && !credProvided) {
    if (anyReachOk) {
      const reached = ['udp', 'tcp', 'tls'].filter(reachOk).map((k) => k.toUpperCase()).join(', ');
      status = 'pass';
      title = 'TURN is reachable — credentials not tested';
      text = 'The server answered the allocation request (401) over ' + reached + ', which proves this network lets you reach the TURN server on those transports — they are not blocked. Relay allocation was not verified because no credentials were provided; add a shared secret or credential to confirm a working relay.';
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
}

function chip(label, s) {
  const icon = { pass: 'i-check', fail: 'i-x', warn: 'i-alert', skip: 'i-dashed' }[s];
  return `<span class="chip" data-s="${s}"><svg class="ic" viewBox="0 0 24 24"><use href="#${icon}"/></svg>${esc(label)}</span>`;
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
  };
  const defs = TEST_DEFS.filter((d) => enabled[d.key]).map((d) => ({ ...d, url: turnUrl(d.key) }));
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
      ${errRows(res.errors)}
      ${credLine}`);
  }

  splashCurrent('Computing verdict');
  diagLog('All probes complete — computing verdict', 'run');
  computeVerdict(results, natInfo, cred.provided);
  diagLog('Done', 'ok');

  await new Promise((r) => setTimeout(r, 600));
  splashHide();

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
  loadConfig();

  if (!window.RTCPeerConnection) {
    $('#empty').innerHTML = '<h3>WebRTC unavailable</h3><p>This browser does not expose RTCPeerConnection, so ICE probing cannot run.</p>';
  }
}

document.addEventListener('DOMContentLoaded', init);
