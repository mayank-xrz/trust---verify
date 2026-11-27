"""Self-contained Security Operations & Track 4 Sandbox Console UI."""

from __future__ import annotations


def render_dashboard_html() -> str:
    """Return the full Track 4 Trust, But Verify web console HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Trust, But Verify — Track 4 PQC & Zero-Trust Control Plane</title>
<style>
  :root {
    --bg: #070b12;
    --panel: #0f1623;
    --panel-2: #161f30;
    --border: #233047;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --cyan: #38bdf8;
    --emerald: #10b981;
    --red: #ef4444;
    --amber: #f59e0b;
    --purple: #a78bfa;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: var(--sans); font-size: 14px; line-height: 1.5;
  }
  a { color: var(--cyan); text-decoration: none; }
  a:hover { text-decoration: underline; }
  header {
    background: linear-gradient(180deg, #11192a 0%, #0b101b 100%);
    border-bottom: 1px solid var(--border);
    padding: 14px 24px;
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 14px;
    position: sticky; top: 0; z-index: 20;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .logo {
    width: 38px; height: 38px; border-radius: 9px;
    background: linear-gradient(135deg, #0ea5e9, #10b981);
    display: grid; place-items: center; font-weight: 800; color: #05101a; font-size: 16px;
  }
  .brand h1 { margin: 0; font-size: 17px; letter-spacing: -0.01em; }
  .brand p { margin: 0; font-size: 12px; color: var(--muted); }
  .badges { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
  .badge {
    font-family: var(--mono); font-size: 11px; padding: 4px 9px;
    border-radius: 999px; border: 1px solid var(--border); background: var(--panel-2);
    color: var(--text); white-space: nowrap;
  }
  .badge.ok { border-color: rgba(16,185,129,0.45); color: #6ee7b7; background: rgba(16,185,129,0.1); }
  .badge.warn { border-color: rgba(245,158,11,0.45); color: #fcd34d; background: rgba(245,158,11,0.1); }
  .badge.bad { border-color: rgba(239,68,68,0.55); color: #fca5a5; background: rgba(239,68,68,0.12); }
  .badge.info { border-color: rgba(56,189,248,0.45); color: #7dd3fc; background: rgba(56,189,248,0.1); }

  .container { max-width: 1380px; margin: 0 auto; padding: 18px 24px 40px; }
  .tabs {
    display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px;
    border-bottom: 1px solid var(--border); padding-bottom: 12px;
  }
  .tab-btn {
    background: var(--panel); border: 1px solid var(--border); color: var(--muted);
    padding: 8px 14px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600;
    transition: all .15s ease;
  }
  .tab-btn:hover { color: var(--text); border-color: #384c6e; }
  .tab-btn.active {
    background: rgba(56,189,248,0.14); color: var(--cyan); border-color: rgba(56,189,248,0.5);
  }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }

  .grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
  .grid-3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
  @media (max-width: 980px) { .grid-2, .grid-3, .grid-4 { grid-template-columns: 1fr; } }

  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 11px; padding: 16px;
  }
  .card h2, .card h3 { margin: 0 0 10px; font-size: 15px; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .sub { color: var(--muted); font-size: 12.5px; margin: 0 0 12px; }

  .btn-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
  button.act {
    background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
    padding: 8px 12px; border-radius: 7px; cursor: pointer; font-size: 12.5px; font-weight: 600;
    transition: transform .05s, border-color .15s, background .15s;
  }
  button.act:hover { border-color: var(--cyan); background: #1c273c; }
  button.act:active { transform: translateY(1px); }
  button.act.primary { background: #0284c7; border-color: #38bdf8; color: #fff; }
  button.act.primary:hover { background: #0369a1; }
  button.act.success { background: rgba(16,185,129,0.16); border-color: rgba(16,185,129,0.5); color: #6ee7b7; }
  button.act.danger { background: rgba(239,68,68,0.15); border-color: rgba(239,68,68,0.5); color: #fca5a5; }
  button.act.warn { background: rgba(245,158,11,0.15); border-color: rgba(245,158,11,0.5); color: #fcd34d; }

  input, select {
    background: #080d16; border: 1px solid var(--border); color: var(--text);
    padding: 8px 10px; border-radius: 7px; font-size: 13px; width: 100%;
  }
  .field { margin-bottom: 10px; }
  .field label { display: block; font-size: 11.5px; color: var(--muted); margin-bottom: 4px; }

  .mono { font-family: var(--mono); font-size: 12px; }
  .kv { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px dashed rgba(255,255,255,0.06); font-size: 12.5px; }
  .kv:last-child { border-bottom: none; }
  .kv span:first-child { color: var(--muted); }

  .arch-flow {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 12px 0;
  }
  @media (max-width: 900px) { .arch-flow { grid-template-columns: 1fr; } }
  .arch-box {
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 9px; padding: 12px;
    border-top: 3px solid var(--cyan);
  }
  .arch-box.green { border-top-color: var(--emerald); }
  .arch-box.amber { border-top-color: var(--amber); }
  .arch-box.purple { border-top-color: var(--purple); }
  .arch-box h4 { margin: 0 0 6px; font-size: 13px; }
  .arch-box ul { margin: 0; padding-left: 16px; color: var(--muted); font-size: 12px; }

  .checklist-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
  @media (max-width: 980px) { .checklist-grid { grid-template-columns: 1fr; } }
  .chk-item {
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px;
    display: flex; flex-direction: column; gap: 4px;
  }
  .chk-item.pass { border-color: rgba(16,185,129,0.5); background: rgba(16,185,129,0.07); }
  .chk-item.fail { border-color: rgba(239,68,68,0.55); background: rgba(239,68,68,0.08); }
  .chk-top { display: flex; justify-content: space-between; align-items: center; font-weight: 600; font-size: 12.5px; }
  .chk-sum { font-size: 11.5px; color: var(--muted); font-family: var(--mono); }

  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; background: var(--panel-2); }
  .hash-pill { font-family: var(--mono); color: #7dd3fc; font-size: 11px; }

  pre.console {
    background: #05080f; border: 1px solid var(--border); border-radius: 8px;
    padding: 12px; font-family: var(--mono); font-size: 11.5px; color: #cbd5e1;
    max-height: 290px; overflow: auto; white-space: pre-wrap; word-break: break-word; margin: 0;
  }
  .alert-card {
    background: rgba(239,68,68,0.07); border: 1px solid rgba(239,68,68,0.35);
    border-radius: 8px; padding: 10px 12px; margin-bottom: 8px;
  }
  .alert-card.CRITICAL { border-color: rgba(239,68,68,0.7); background: rgba(239,68,68,0.12); }
  .alert-card.HIGH { border-color: rgba(245,158,11,0.55); background: rgba(245,158,11,0.09); }

  .score-bar {
    height: 8px; background: #1e293b; border-radius: 999px; overflow: hidden; margin-top: 8px;
  }
  .score-fill { height: 100%; background: linear-gradient(90deg, #0ea5e9, #10b981); width: 0%; transition: width .3s ease; }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo">TBV</div>
    <div>
      <h1>Trust, But Verify — Track 4 Zero-Trust PQC Console</h1>
      <p>Post-Quantum Cryptography, Atomic Key Lifecycle, Tamper-Evident Audit &amp; Explainable Detection</p>
    </div>
  </div>
  <div class="badges">
    <span id="hdr-pqc" class="badge info">PQC: Loading...</span>
    <span id="hdr-aiml" class="badge ok">Zero AI/ML Rules</span>
    <span id="hdr-chain" class="badge ok">Audit Chain: Checking</span>
    <span id="hdr-score" class="badge warn">Checklist: 0/12</span>
    <a class="badge" href="/docs" target="_blank">Swagger /docs</a>
    <button class="act primary" id="btn-run-all" onclick="runAll12()">Run All 12 Scenarios</button>
  </div>
</header>

<div class="container">
  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('overview', this)">1. Overview &amp; Checklist</button>
    <button class="tab-btn" onclick="switchTab('messaging', this)">2. PQC Messaging &amp; Attacks</button>
    <button class="tab-btn" onclick="switchTab('lifecycle', this)">3. Key Lifecycle &amp; Chaos</button>
    <button class="tab-btn" onclick="switchTab('audit', this)">4. Tamper-Evident Audit</button>
    <button class="tab-btn" onclick="switchTab('detector', this)">5. Explainable Detector</button>
    <button class="tab-btn" onclick="switchTab('threat', this)">6. 1-Page Threat Model</button>
  </div>

  <!-- TAB 1: OVERVIEW -->
  <div id="tab-overview" class="tab-panel active">
    <div class="card" style="margin-bottom:16px;">
      <h2>
        <span>System Architecture — Control, Data, Audit &amp; Explainable Detection Planes</span>
        <span class="mono" id="uptime-lbl" style="color:var(--muted);">uptime: --</span>
      </h2>
      <div class="arch-flow">
        <div class="arch-box">
          <h4>Control Plane (Identity)</h4>
          <ul>
            <li>Atomic Rotation + Grace Cutoff</li>
            <li>Cross-Node Revocation Broadcast</li>
            <li>WAL Crash Recovery &amp; Re-Enroll</li>
            <li>HMAC-SHA3-512 Backups</li>
          </ul>
        </div>
        <div class="arch-box green">
          <h4>Data Plane (PQC E2EE)</h4>
          <ul>
            <li>NIST ML-KEM-768 Ephemeral KEM</li>
            <li>NIST ML-DSA-65 Signatures</li>
            <li>AES-256-GCM + Recipient AAD</li>
            <li>256-Seq Anti-Replay Window</li>
          </ul>
        </div>
        <div class="arch-box amber">
          <h4>Tamper-Evident Audit</h4>
          <ul>
            <li>SHA-256 Continuous Hash Chain</li>
            <li>Newline/JSON Escape Sanitizer</li>
            <li>1-Byte Mutation Detection</li>
            <li>Operator Log Chain Verifier</li>
          </ul>
        </div>
        <div class="arch-box purple">
          <h4>Explainable Detector</h4>
          <ul>
            <li>Strict Microservice DAG Policy</li>
            <li>Context Privilege Rules</li>
            <li>&plusmn;2000ms Clock-Skew Buffer</li>
            <li>F1 / MTTA / FP-per-1k Metrics</li>
          </ul>
        </div>
      </div>
    </div>

    <div class="grid-3" id="nodes-grid" style="margin-bottom:16px;"></div>

    <div class="card" style="margin-bottom:16px;">
      <h2>
        <span>Track 4 Challenge Checklist (Live Functional Verification)</span>
        <span class="mono" id="chk-count-lbl">0 / 12 Verified</span>
      </h2>
      <div class="score-bar"><div class="score-fill" id="chk-bar"></div></div>
      <div class="checklist-grid" id="checklist-grid" style="margin-top:12px;"></div>
    </div>
  </div>

  <!-- TAB 2: PQC MESSAGING -->
  <div id="tab-messaging" class="tab-panel">
    <div class="grid-2">
      <div class="card">
        <h2>End-to-End Protected Transfer (node-a &rarr; node-b)</h2>
        <p class="sub">Establishes an ephemeral ML-KEM session secret, seals plaintext with AES-256-GCM + Recipient Binding AAD, and signs with ML-DSA.</p>
        <div class="field">
          <label>Confidential Payload Message</label>
          <input id="msg-input" value="Approve wire #8841: $25,000 Treasury -> Escrow-B" />
        </div>
        <div class="btn-row">
          <button class="act primary" onclick="apiCall('/api/sandbox/pqc-transfer', {message: document.getElementById('msg-input').value}, 'msg-out')">Send PQC Envelope</button>
          <button class="act danger" onclick="apiCall('/api/sandbox/attack/replay', {}, 'msg-out')">Simulate Replay Attack</button>
          <button class="act danger" onclick="apiCall('/api/sandbox/attack/recipient-swap', {}, 'msg-out')">Simulate Recipient Swap (node-c)</button>
        </div>
        <div class="btn-row">
          <button class="act warn" onclick="apiCall('/api/sandbox/attack/forward-secrecy', {}, 'msg-out')">Verify Forward Secrecy (Wipe &amp; Leak ID Key)</button>
          <button class="act warn" onclick="apiCall('/api/sandbox/attack/session-resumption', {}, 'msg-out')">Test Session Hijack (Mallory)</button>
          <button class="act success" onclick="apiCall('/api/sandbox/attack/loss-reorder', {}, 'msg-out')">Test Loss &amp; Reordering</button>
        </div>
      </div>
      <div class="card">
        <h2>Cryptographic Verification Output</h2>
        <pre class="console" id="msg-out">Click any action on the left to run live PQC cryptographic operations and view raw envelope metadata &amp; attack verdicts.</pre>
      </div>
    </div>
  </div>

  <!-- TAB 3: KEY LIFECYCLE & CHAOS -->
  <div id="tab-lifecycle" class="tab-panel">
    <div class="grid-2">
      <div class="card">
        <h2>Atomic Rotation, Grace Period &amp; Cross-Node Revocation</h2>
        <p class="sub">Rotate keys with a configurable grace cutoff, prove old keys succeed inside grace and fail across all 3 nodes post-cutoff, then revoke &amp; re-enroll.</p>
        <div class="field">
          <label>Grace Period Seconds (e.g. 3.0s for live testing)</label>
          <input id="grace-sec" type="number" step="0.5" min="0.5" max="30" value="3.0" />
        </div>
        <div class="btn-row">
          <button class="act primary" onclick="apiCall('/api/sandbox/lifecycle/rotate', {grace_seconds: parseFloat(document.getElementById('grace-sec').value || '3')}, 'life-out')">1. Rotate Key (Start Grace)</button>
          <button class="act warn" onclick="apiCall('/api/sandbox/lifecycle/test-old-key', {}, 'life-out')">2. Test Old Key (All 3 Nodes)</button>
        </div>
        <div class="btn-row" style="margin-top:12px;">
          <button class="act danger" onclick="apiCall('/api/sandbox/lifecycle/revoke-and-reenroll', {mode: 'revoke'}, 'life-out')">3. Revoke Alice Key (Measure ms)</button>
          <button class="act success" onclick="apiCall('/api/sandbox/lifecycle/revoke-and-reenroll', {mode: 'reenroll'}, 'life-out')">4. Re-Enroll Alice New Device</button>
        </div>
        <hr style="border:none;border-top:1px solid var(--border);margin:16px 0;" />
        <h3>Crash Recovery (WAL) &amp; Backup Integrity</h3>
        <div class="btn-row">
          <button class="act warn" onclick="apiCall('/api/sandbox/resilience/crash-recovery', {}, 'life-out')">Simulate Mid-Rotation Crash (WAL)</button>
          <button class="act success" onclick="apiCall('/api/sandbox/resilience/backup', {tamper: false}, 'life-out')">Verify Signed Backup</button>
          <button class="act danger" onclick="apiCall('/api/sandbox/resilience/backup', {tamper: true}, 'life-out')">Corrupt 1 Byte &amp; Restore</button>
        </div>
      </div>
      <div class="card">
        <h2>Identity State &amp; Lifecycle Output</h2>
        <div id="id-status-box" style="margin-bottom:10px;"></div>
        <pre class="console" id="life-out">Trigger rotation, grace cutoff tests, revocation propagation, WAL crash recovery, or backup verification.</pre>
      </div>
    </div>
  </div>

  <!-- TAB 4: TAMPER-EVIDENT AUDIT -->
  <div id="tab-audit" class="tab-panel">
    <div class="card" style="margin-bottom:16px;">
      <h2>
        <span>Cryptographic Audit Log Chain (H<sub>i</sub> = SHA-256(H<sub>i-1</sub> || canonical(E<sub>i</sub>)))</span>
        <span id="audit-badge" class="badge ok">Checking...</span>
      </h2>
      <div class="btn-row" style="margin-bottom:12px;">
        <button class="act primary" onclick="apiCall('/api/sandbox/audit/tamper', {action: 'verify'}, 'audit-out')">Verify Log Chain</button>
        <button class="act warn" onclick="apiCall('/api/sandbox/audit/injection', {}, 'audit-out')">Test Newline/JSON Injection</button>
        <button class="act danger" onclick="apiCall('/api/sandbox/audit/tamper', {action: 'tamper'}, 'audit-out')">Verify a Tampered Copy</button>
      </div>
      <pre class="console" id="audit-out" style="max-height:140px;margin-bottom:12px;">Run chain verification, newline injection test, or 1-byte mutation test.</pre>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr><th>Seq</th><th>Service</th><th>Action</th><th>Subject / Actor</th><th>Status</th><th>Entry Hash</th></tr>
          </thead>
          <tbody id="audit-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 5: EXPLAINABLE DETECTOR -->
  <div id="tab-detector" class="tab-panel">
    <div class="grid-2" style="margin-bottom:16px;">
      <div class="card">
        <h2>Explainable Rules, Lateral Movement DAG &amp; Clock Skew</h2>
        <p class="sub">100% deterministic graph &amp; context-rule engine (zero AI/ML). Flags privilege abuse, lateral service hops, and out-of-order timing skew.</p>
        <div class="btn-row">
          <button class="act danger" onclick="apiCall('/api/sandbox/detector/lateral-movement', {}, 'det-out')">Simulate Lateral Movement (audit &rarr; node-c)</button>
          <button class="act danger" onclick="apiCall('/api/sandbox/detector/privilege-escalation', {}, 'det-out')">Simulate Privilege Gain (guest &rarr; admin)</button>
        </div>
        <div class="btn-row">
          <button class="act warn" onclick="apiCall('/api/sandbox/detector/clock-skew', {}, 'det-out')">Test Clock Skew (&plusmn;2000ms + Flag)</button>
          <button class="act primary" onclick="apiCall('/api/sandbox/detector/eval-metrics', {}, 'det-out')">Run Synthetic Detector Check</button>
        </div>
        <div id="eval-metrics-box" style="margin-top:12px;"></div>
        <pre class="console" id="det-out" style="margin-top:12px;">Run lateral movement, privilege escalation, clock-skew ordering, or F1/MTTA benchmark.</pre>
      </div>
      <div class="card">
        <h2>Live Explainable Alerts Feed</h2>
        <div id="alerts-feed" style="max-height:430px;overflow:auto;"></div>
      </div>
    </div>
  </div>

  <!-- TAB 6: THREAT MODEL -->
  <div id="tab-threat" class="tab-panel">
    <div class="grid-2">
      <div class="card">
        <h2>1. Protected Assets &amp; Adversary Model</h2>
        <div class="kv"><span>In-Flight Payloads</span><span>AES-256-GCM + Recipient Binding AAD</span></div>
        <div class="kv"><span>Node Identity Keys</span><span>NIST FIPS 204 ML-DSA-65 (volatile RAM)</span></div>
        <div class="kv"><span>Session Secrets</span><span>NIST FIPS 203 ML-KEM-768 (ephemeral wipe)</span></div>
        <div class="kv"><span>Key State &amp; Backups</span><span>Fsynced WAL + HMAC-SHA3-512 snapshots</span></div>
        <div class="kv"><span>Audit Forensics</span><span>SHA-256 continuous hash chain</span></div>
        <hr style="border:none;border-top:1px solid var(--border);margin:12px 0;" />
        <h3>Threat Actors Addressed</h3>
        <ul style="color:var(--muted);padding-left:18px;font-size:12.5px;">
          <li><strong>Harvest-Now-Decrypt-Later (HNDL):</strong> Passive traffic capture decrypted by future CRQCs running Shor's algorithm.</li>
          <li><strong>Network MITM:</strong> Replay, sequence reordering, and recipient-swap redirection attacks.</li>
          <li><strong>Compromised Service Node / Insider:</strong> Valid credential misuse attempting unauthorized lateral hops.</li>
          <li><strong>Log-Injection Attacker:</strong> Embedded newline/JSON forgery or post-compromise file tampering.</li>
        </ul>
      </div>
      <div class="card">
        <h2>2. Trust Assumptions &amp; Honest System Limits</h2>
        <ul style="color:var(--muted);padding-left:18px;font-size:12.5px;line-height:1.65;">
          <li><strong>Zero AI/ML Hallucination:</strong> Detection relies purely on O(1) DAG edge checks and deterministic rules; zero model drift or adversarial ML evasion.</li>
          <li><strong>Clock-Skew Boundary (&plusmn;2000ms):</strong> Events within &plusmn;2000ms are buffered and ordered; events exceeding tolerance are preserved but flagged <span class="mono">UNCERTAIN_TIMING / CLOCK_SKEW_EXCEEDED</span>.</li>
          <li><strong>Network Partition Trade-off:</strong> Partitioned nodes fail closed once grace cutoffs expire until revocation gossip sync resumes.</li>
          <li><strong>Metadata Visibility:</strong> L7 routing headers (<span class="mono">sender_id</span>, <span class="mono">recipient_id</span>) remain visible for recipient binding verification.</li>
          <li><strong>Sandbox Prototype Scope:</strong> Keys reside in volatile container memory rather than physical TPM/HSM enclaves (production requires AMD SEV / KMS sealing).</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<script>
function switchTab(id, btn) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  if (btn) btn.classList.add('active');
}

async function apiCall(url, body, outId) {
  const out = outId ? document.getElementById(outId) : null;
  if (out) out.textContent = 'Running ' + url + ' ...';
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body || {})
    });
    const data = await res.json();
    if (out) out.textContent = JSON.stringify(data, null, 2);
    await refreshState();
    return data;
  } catch (err) {
    if (out) out.textContent = 'Error: ' + err;
  }
}

async function refreshState() {
  try {
    const res = await fetch('/api/sandbox/state');
    const s = await res.json();

    document.getElementById('uptime-lbl').textContent = 'uptime: ' + s.uptime_seconds + 's';
    const pqcTag = s.crypto.native_liboqs ? 'liboqs native' : 'RFC3526 fallback';
    document.getElementById('hdr-pqc').textContent = `PQC: ${s.crypto.kem_algorithm} + ${s.crypto.sig_algorithm} (${pqcTag})`;

    const chainOk = s.audit.verification && s.audit.verification.is_valid;
    const chainBadge = document.getElementById('hdr-chain');
    const auditBadge = document.getElementById('audit-badge');
    chainBadge.textContent = chainOk ? `Audit Chain: VALID (${s.audit.verification.total_records})` : 'Audit Chain: TAMPERED!';
    chainBadge.className = 'badge ' + (chainOk ? 'ok' : 'bad');
    auditBadge.textContent = chainOk ? `VALID (${s.audit.verification.total_records} records)` : `TAMPER DETECTED (seq ${s.audit.verification.corrupted_sequence})`;
    auditBadge.className = 'badge ' + (chainOk ? 'ok' : 'bad');

    const scoreBadge = document.getElementById('hdr-score');
    scoreBadge.textContent = `Checklist: ${s.checklist_passed}/${s.checklist_total}`;
    scoreBadge.className = 'badge ' + (s.checklist_passed === s.checklist_total ? 'ok' : 'warn');
    document.getElementById('chk-count-lbl').textContent = `${s.checklist_passed} / ${s.checklist_total} Verified`;
    document.getElementById('chk-bar').style.width = ((s.checklist_passed / s.checklist_total) * 100) + '%';

    // Render Nodes
    document.getElementById('nodes-grid').innerHTML = s.nodes.map(n => `
      <div class="card">
        <h3><span>${n.node_id}</span><span class="badge ${n.active_key_id ? 'ok' : 'bad'}">${n.active_key_id ? 'ACTIVE v' + n.active_version : 'KEY REVOKED'}</span></h3>
        <div class="kv"><span>Active Key</span><span class="mono">${n.active_key_id || 'NONE'}</span></div>
        <div class="kv"><span>Grace Keys</span><span class="mono">${n.grace_keys_count} ${n.remaining_grace_sec > 0 ? '(' + n.remaining_grace_sec + 's left)' : ''}</span></div>
        <div class="kv"><span>Revoked / Expired</span><span class="mono">${n.revoked_count} / ${n.expired_count}</span></div>
      </div>
    `).join('');

    // Render Checklist
    document.getElementById('checklist-grid').innerHTML = s.checklist.map(c => `
      <div class="chk-item ${c.status}">
        <div class="chk-top">
          <span>${c.label}</span>
          <span class="badge ${c.status === 'pass' ? 'ok' : 'warn'}">${c.status === 'pass' ? 'PASS' : 'PENDING'}</span>
        </div>
        <div class="chk-sum">${c.summary}</div>
      </div>
    `).join('');

    // Identity Status Box
    const al = s.identities.alice;
    const bo = s.identities.bob;
    document.getElementById('id-status-box').innerHTML = `
      <div class="kv"><span>Alice (${al.device_id})</span><span class="badge ${al.status === 'active' ? 'ok' : 'bad'}">${al.status.toUpperCase()} (${al.active_key_id || al.revoked_key_id})</span></div>
      <div class="kv"><span>Bob (${bo.device_id})</span><span class="badge ok">ACTIVE (${bo.active_key_id})</span></div>
      <div class="kv"><span>Last Revocation Latency</span><span class="mono">${s.revocation_propagation_ms !== null ? s.revocation_propagation_ms + ' ms' : 'Not yet measured'}</span></div>
    `;

    // Audit Table
    document.getElementById('audit-tbody').innerHTML = (s.audit.recent_entries || []).map(r => `
      <tr>
        <td class="mono">${r.sequence ?? '-'}</td>
        <td class="mono">${r.service || '-'}</td>
        <td class="mono">${r.action || '-'}</td>
        <td class="mono">${(r.subject || '-').slice(0, 38)}</td>
        <td><span class="badge ${r.status === 'SUCCESS' ? 'ok' : 'bad'}">${r.status || '-'}</span></td>
        <td class="hash-pill">${(r.entry_hash || '').slice(0, 18)}...</td>
      </tr>
    `).join('');

    // Alerts Feed
    const alerts = s.alerts || [];
    document.getElementById('alerts-feed').innerHTML = alerts.length === 0
      ? '<p class="sub">No alerts recorded yet. Run any attack simulation to inspect explainable evidence.</p>'
      : alerts.map(a => `
        <div class="alert-card ${a.severity || 'HIGH'}">
          <div style="display:flex;justify-content:space-between;font-weight:700;font-size:12.5px;">
            <span>[${a.severity || 'HIGH'}] ${a.rule_name}</span>
            <span class="mono" style="color:var(--muted);">${a.service || ''}</span>
          </div>
          <div style="font-size:12.5px;margin:4px 0;">${a.description || ''}</div>
          <div class="mono" style="font-size:11px;color:var(--muted);overflow-wrap:anywhere;">Subject: ${a.subject || '-'} | Evidence: ${JSON.stringify(a.evidence || {})}</div>
        </div>
      `).join('');

    // Eval Metrics
    if (s.eval_metrics) {
      const m = s.eval_metrics;
      document.getElementById('eval-metrics-box').innerHTML = `
        <div class="grid-4">
          <div class="chk-item pass"><span class="mono">F1 Score</span><strong>${m.f1_score}</strong></div>
          <div class="chk-item pass"><span class="mono">Precision / Recall</span><strong>${m.precision} / ${m.recall}</strong></div>
          <div class="chk-item pass"><span class="mono">Median time to alert</span><strong>${m.median_time_to_alert_ms} ms</strong></div>
          <div class="chk-item pass"><span class="mono">False alerts / 1k benign events</span><strong>${m.false_alerts_per_1k}</strong></div>
        </div>
      `;
    }
  } catch (e) {
    console.error('State refresh failed:', e);
  }
}

async function runAll12() {
  const btn = document.getElementById('btn-run-all');
  btn.disabled = true;
  btn.textContent = 'Running 12 Scenarios...';
  try {
    await apiCall('/api/sandbox/pqc-transfer', {message: 'Auto-Audit Verified Wire #101'});
    await apiCall('/api/sandbox/attack/replay', {});
    await apiCall('/api/sandbox/attack/recipient-swap', {});
    await apiCall('/api/sandbox/attack/forward-secrecy', {});
    await apiCall('/api/sandbox/attack/session-resumption', {});
    await apiCall('/api/sandbox/attack/loss-reorder', {});
    await apiCall('/api/sandbox/lifecycle/rotate', {grace_seconds: 1.0});
    await apiCall('/api/sandbox/lifecycle/test-old-key', {});
    await new Promise(r => setTimeout(r, 1150));
    await apiCall('/api/sandbox/lifecycle/test-old-key', {});
    await apiCall('/api/sandbox/lifecycle/revoke-and-reenroll', {mode: 'revoke'});
    await apiCall('/api/sandbox/lifecycle/revoke-and-reenroll', {mode: 'reenroll'});
    await apiCall('/api/sandbox/resilience/crash-recovery', {});
    await apiCall('/api/sandbox/resilience/backup', {tamper: false});
    await apiCall('/api/sandbox/resilience/backup', {tamper: true});
    await apiCall('/api/sandbox/audit/injection', {});
    await apiCall('/api/sandbox/detector/lateral-movement', {});
    await apiCall('/api/sandbox/detector/privilege-escalation', {});
    await apiCall('/api/sandbox/detector/clock-skew', {});
    await apiCall('/api/sandbox/detector/eval-metrics', {});
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run All 12 Scenarios';
    await refreshState();
  }
}

refreshState();
setInterval(refreshState, 4000);
</script>
</body>
</html>
"""
