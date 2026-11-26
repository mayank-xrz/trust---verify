"""Self-contained Security Operations & Track 4 Interactive Workbench UI."""

from __future__ import annotations


def render_dashboard_html() -> str:
    """Return the full Track 4 Trust, But Verify interactive workbench HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Trust, But Verify — Track 4 PQC &amp; Zero-Trust Workbench</title>
<style>
  :root {
    --bg: #060a11;
    --panel: #0e1522;
    --panel-2: #151f31;
    --border: #24324a;
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
    background: linear-gradient(180deg, #10192b 0%, #090e18 100%);
    border-bottom: 1px solid var(--border);
    padding: 13px 24px;
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 14px;
    position: sticky; top: 0; z-index: 30;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .logo {
    width: 40px; height: 40px; border-radius: 10px;
    background: linear-gradient(135deg, #0ea5e9, #10b981);
    display: grid; place-items: center; font-weight: 800; color: #041019; font-size: 15px;
    box-shadow: 0 0 18px rgba(14,165,233,0.28);
  }
  .brand h1 { margin: 0; font-size: 16.5px; letter-spacing: -0.01em; }
  .brand p { margin: 0; font-size: 12px; color: var(--muted); }
  .badges { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; }
  .badge {
    font-family: var(--mono); font-size: 11px; padding: 4px 9px;
    border-radius: 999px; border: 1px solid var(--border); background: var(--panel-2);
    color: var(--text); white-space: nowrap;
  }
  .badge.ok { border-color: rgba(16,185,129,0.45); color: #6ee7b7; background: rgba(16,185,129,0.1); }
  .badge.warn { border-color: rgba(245,158,11,0.45); color: #fcd34d; background: rgba(245,158,11,0.1); }
  .badge.bad { border-color: rgba(239,68,68,0.55); color: #fca5a5; background: rgba(239,68,68,0.12); }
  .badge.info { border-color: rgba(56,189,248,0.45); color: #7dd3fc; background: rgba(56,189,248,0.1); }
  .badge.purple { border-color: rgba(167,139,250,0.45); color: #ddd6fe; background: rgba(167,139,250,0.12); }

  .container { max-width: 1440px; margin: 0 auto; padding: 18px 24px 48px; }
  .tabs {
    display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px;
    border-bottom: 1px solid var(--border); padding-bottom: 12px;
  }
  .tab-btn {
    background: var(--panel); border: 1px solid var(--border); color: var(--muted);
    padding: 8px 13px; border-radius: 8px; cursor: pointer; font-size: 12.5px; font-weight: 600;
    transition: all .15s ease;
  }
  .tab-btn:hover { color: var(--text); border-color: #384c6e; }
  .tab-btn.active {
    background: rgba(56,189,248,0.14); color: var(--cyan); border-color: rgba(56,189,248,0.55);
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
    padding: 7px 12px; border-radius: 7px; cursor: pointer; font-size: 12.5px; font-weight: 600;
    transition: transform .05s, border-color .15s, background .15s;
  }
  button.act:hover { border-color: var(--cyan); background: #1c273c; }
  button.act:active { transform: translateY(1px); }
  button.act:disabled { opacity: 0.6; cursor: wait; }
  button.act.primary { background: #0284c7; border-color: #38bdf8; color: #fff; }
  button.act.primary:hover { background: #0369a1; }
  button.act.success { background: rgba(16,185,129,0.16); border-color: rgba(16,185,129,0.5); color: #6ee7b7; }
  button.act.danger { background: rgba(239,68,68,0.15); border-color: rgba(239,68,68,0.5); color: #fca5a5; }
  button.act.warn { background: rgba(245,158,11,0.15); border-color: rgba(245,158,11,0.5); color: #fcd34d; }
  button.act.purple { background: rgba(167,139,250,0.16); border-color: rgba(167,139,250,0.5); color: #ddd6fe; }

  input, select, textarea {
    background: #080d16; border: 1px solid var(--border); color: var(--text);
    padding: 8px 10px; border-radius: 7px; font-size: 13px; width: 100%;
    font-family: inherit;
  }
  input[type="checkbox"] { width: auto; }
  textarea { font-family: var(--mono); font-size: 11.5px; min-height: 92px; resize: vertical; }
  .field { margin-bottom: 10px; }
  .field label { display: block; font-size: 11.5px; color: var(--muted); margin-bottom: 4px; }
  .row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .row-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; }
  @media (max-width: 720px) { .row-2, .row-3 { grid-template-columns: 1fr; } }

  .mono { font-family: var(--mono); font-size: 12px; }
  .kv { display: flex; justify-content: space-between; gap: 10px; padding: 5px 0; border-bottom: 1px dashed rgba(255,255,255,0.06); font-size: 12.5px; }
  .kv:last-child { border-bottom: none; }
  .kv span:first-child { color: var(--muted); }

  .verdict-box {
    border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px;
    margin-bottom: 10px; background: var(--panel-2);
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px;
  }
  .verdict-box.ok { border-color: rgba(16,185,129,0.55); background: rgba(16,185,129,0.09); }
  .verdict-box.blocked { border-color: rgba(245,158,11,0.55); background: rgba(245,158,11,0.1); }
  .verdict-box.bad { border-color: rgba(239,68,68,0.55); background: rgba(239,68,68,0.1); }
  .verdict-title { font-weight: 700; font-size: 13px; }
  .verdict-sub { font-size: 12px; color: var(--muted); font-family: var(--mono); }

  .dropzone {
    border: 2px dashed #33486b; border-radius: 10px; padding: 18px;
    background: #080d16; text-align: center; cursor: pointer;
    transition: border-color .15s, background .15s;
  }
  .dropzone.drag { border-color: var(--cyan); background: rgba(56,189,248,0.08); }
  .file-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
  .file-chip {
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 999px;
    padding: 3px 10px; font-family: var(--mono); font-size: 11px; color: #bae6fd;
  }

  .test-list {
    max-height: 220px; overflow: auto; border: 1px solid var(--border);
    border-radius: 8px; background: #080d16; padding: 8px;
  }
  .test-item {
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    padding: 4px 6px; border-bottom: 1px dashed rgba(255,255,255,0.05); font-family: var(--mono); font-size: 11.5px;
  }
  .test-item label { display: flex; align-items: center; gap: 8px; cursor: pointer; }

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
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
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

  .dag-wrap {
    background: #05080f; border: 1px solid var(--border); border-radius: 9px; padding: 10px; margin-top: 10px;
  }
  .cmd-line {
    background: #05080f; border: 1px solid var(--border); border-radius: 7px; padding: 8px 10px;
    display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 8px;
  }
  .cmd-line code { font-family: var(--mono); font-size: 11.5px; color: #7dd3fc; word-break: break-all; }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo">TBV</div>
    <div>
      <h1>Trust, But Verify &mdash; Track 4 PQC &amp; Zero-Trust Workbench</h1>
      <p>NIST ML-KEM / ML-DSA / SLH-DSA &bull; Upload &amp; Verify Test Files &bull; 20 MiB &amp; 1-Device Policy &bull; Authority Rollback</p>
    </div>
  </div>
  <div class="badges">
    <span id="hdr-pqc" class="badge info">PQC: Loading...</span>
    <span id="hdr-policy" class="badge ok">20 MiB | 1 Device/User</span>
    <span id="hdr-aiml" class="badge ok">Zero AI/ML Rules</span>
    <span id="hdr-chain" class="badge ok">Audit Chain: Checking</span>
    <span id="hdr-score" class="badge warn">Checklist: 0/12</span>
    <a class="badge" href="/docs" target="_blank">Swagger /docs</a>
    <button class="act primary" id="btn-run-all" onclick="runAll12()">Run All 12 Scenarios</button>
  </div>
</header>

<div class="container">
  <div class="tabs">
    <button class="tab-btn active" data-tab="overview" onclick="switchTab('overview')">1. Overview &amp; Checklist</button>
    <button class="tab-btn" data-tab="tests" onclick="switchTab('tests')">2. Test Files &amp; Pytest Runner</button>
    <button class="tab-btn" data-tab="messaging" onclick="switchTab('messaging')">3. PQC Messaging &amp; File Guard</button>
    <button class="tab-btn" data-tab="lifecycle" onclick="switchTab('lifecycle')">4. Keys, Devices &amp; Authority</button>
    <button class="tab-btn" data-tab="audit" onclick="switchTab('audit')">5. Audit Chain &amp; Adapter</button>
    <button class="tab-btn" data-tab="detector" onclick="switchTab('detector')">6. Detector &amp; Practice Logs</button>
    <button class="tab-btn" data-tab="threat" onclick="switchTab('threat')">7. Guide &amp; Threat Model</button>
  </div>

  <!-- TAB 1: OVERVIEW -->
  <div id="tab-overview" class="tab-panel active">
    <div class="verdict-box ok" style="margin-bottom:16px;">
      <div>
        <div class="verdict-title">Verify Your Own Test Files, Event CSVs, Audit Logs, or Repo Suites</div>
        <div class="verdict-sub">Drop <code>events.csv</code> + <code>approvals.json</code> + <code>labels.csv</code>, <code>*.log</code> hash chains, <code>tests/test_*.py</code>, <code>track4_service.py</code>, or media files for instant verification.</div>
      </div>
      <button class="act primary" onclick="switchTab('tests')">Open Test Files &amp; Verifier &rarr;</button>
    </div>

    <div class="card" style="margin-bottom:16px;">
      <h2>
        <span>Zero-Trust System Planes &amp; Active Security Controls</span>
        <span class="mono" id="uptime-lbl" style="color:var(--muted);">uptime: --</span>
      </h2>
      <div class="arch-flow">
        <div class="arch-box">
          <h4>Control &amp; Identity Plane</h4>
          <ul>
            <li>Atomic Rotation + Grace Cutoff</li>
            <li>Cross-Node Revocation Broadcast</li>
            <li>WAL Crash Recovery &amp; Re-Enroll</li>
            <li>HMAC-SHA3-512 Backups</li>
          </ul>
        </div>
        <div class="arch-box green">
          <h4>Data &amp; PQC Agility Plane</h4>
          <ul>
            <li>v1: X25519 + ML-KEM-768 + ML-DSA-65</li>
            <li>v2-paranoid: + ML-KEM-1024 + HQC-256 + SLH-DSA</li>
            <li>20 MiB Cap &amp; Magic-Byte Media Guard</li>
            <li>1-Device Lock + Timezone Anomaly Block</li>
          </ul>
        </div>
        <div class="arch-box amber">
          <h4>Audit &amp; Authority Guard</h4>
          <ul>
            <li>SHA-256 Continuous Hash Chain</li>
            <li>Newline/JSON Escape Sanitizer</li>
            <li>1-Byte Mutation Fail-Closed Check</li>
            <li>Suspicious Admin Revert-to-Snapshot</li>
          </ul>
        </div>
        <div class="arch-box purple">
          <h4>Explainable Detector</h4>
          <ul>
            <li>Strict Microservice DAG Policy</li>
            <li>Approved vs Unapproved Role Rules</li>
            <li>&plusmn;2000ms Clock-Skew &amp; Offset Sync</li>
            <li>Track-4 Adapter Interop Runner</li>
          </ul>
        </div>
      </div>
      <div class="grid-4" id="policy-overview-strip" style="margin-top:8px;"></div>
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

  <!-- TAB 2: UNIVERSAL TEST FILES & PYTEST RUNNER -->
  <div id="tab-tests" class="tab-panel">
    <div class="grid-2" style="margin-bottom:16px;">
      <div class="card">
        <h2>Drop or Select Any Test Files to Verify Automatically</h2>
        <p class="sub">Select one or multiple files at once &mdash; auto-detects and verifies:</p>
        <ul style="color:var(--muted);padding-left:18px;font-size:12px;margin:0 0 10px;">
          <li><strong>Practice / Event Logs:</strong> <code>events.csv</code> + optional <code>approvals.json</code> + optional <code>labels.csv</code> &rarr; role escalation, lateral movement, clock offsets &amp; label accuracy.</li>
          <li><strong>Audit Logs &amp; Adapter State:</strong> <code>*.log</code> / <code>*.jsonl</code> / <code>state.json</code> &rarr; SHA-256 hash chain &amp; tamper detection.</li>
          <li><strong>Repo Test Suites &amp; Adapter:</strong> <code>tests/test_*.py</code> &rarr; runs live <code>pytest</code>; <code>track4_service.py</code> &rarr; runs Track-4-Toolkit validator + ML-KEM-768 proof.</li>
          <li><strong>JSON Schemas &amp; Media Files:</strong> envelopes, key states, approvals, images/PDFs/scripts (&le; 20 MiB + magic bytes).</li>
        </ul>

        <div id="bundle-dropzone" class="dropzone" onclick="document.getElementById('bundle-picker').click()">
          <div style="font-weight:700;font-size:13.5px;">Click to Choose Test Files or Drag &amp; Drop Here</div>
          <div class="mono" style="color:var(--muted);font-size:11.5px;margin-top:4px;">Supports multiple files at once (CSV, JSON, LOG, PY, PNG, PDF, SH...)</div>
          <input id="bundle-picker" type="file" multiple style="display:none;" onchange="handleBundleFiles(this.files)" />
        </div>
        <div id="bundle-chips" class="file-chips"></div>
        <div class="btn-row" style="margin-top:12px;">
          <button class="act primary" id="btn-check-bundle" onclick="checkSelectedBundle()">Check Uploaded Test Files</button>
          <button class="act" onclick="clearBundleFiles()">Clear Selection</button>
        </div>
      </div>

      <div class="card">
        <h2>Repository Pytest Suites &amp; Track-4-Toolkit Runner</h2>
        <p class="sub">Run verified test files from <code>tests/</code> or run the official <code>Track-4-Toolkit/validate.py</code> lost-device harness directly.</p>
        <div class="btn-row" style="margin-bottom:8px;">
          <button class="act primary" onclick="runSelectedTests(false)">Run Checked Suites (pytest)</button>
          <button class="act success" onclick="runSelectedTests(true)">Run Track-4-Toolkit Validator</button>
          <button class="act purple" onclick="runAllPytestSuites()">Run Full Pytest Suite</button>
        </div>
        <div style="margin-bottom:8px;display:flex;gap:8px;align-items:center;">
          <button class="act" onclick="toggleAllTests(true)">Select All</button>
          <button class="act" onclick="toggleAllTests(false)">Select None</button>
          <span id="repo-tests-meta" class="mono" style="color:var(--muted);">Loading test suites...</span>
        </div>
        <div id="repo-tests-list" class="test-list">Loading...</div>
      </div>
    </div>

    <div class="card">
      <h2>
        <span>File &amp; Test Suite Verification Results</span>
        <span id="bundle-status-badge" class="badge info">Waiting for files or test run</span>
      </h2>
      <div id="bundle-verdict" class="verdict-box">
        <div>
          <div class="verdict-title">No files checked yet</div>
          <div class="verdict-sub">Drop test files on the left or run a pytest / Track-4-Toolkit check on the right.</div>
        </div>
      </div>
      <div id="bundle-results-wrap" style="overflow-x:auto;margin-bottom:12px;"></div>
      <div id="bundle-triage-wrap" style="overflow-x:auto;margin-bottom:12px;"></div>
      <pre class="console" id="bundle-raw-out" style="max-height:260px;">Detailed JSON, pytest output, or Track-4-Toolkit validator output will appear here.</pre>
    </div>
  </div>

  <!-- TAB 3: PQC MESSAGING & FILE GUARD -->
  <div id="tab-messaging" class="tab-panel">
    <div class="grid-2">
      <div>
        <div class="card" style="margin-bottom:16px;">
          <h2>Encrypted Envelope &amp; Cryptographic Agility</h2>
          <p class="sub">Test standard Track 4 hybrid handshakes (<code>v1</code>) or multi-family post-quantum defense (<code>v2-paranoid</code> combining lattice ML-KEM-1024, code-based HQC-256, and hash-based SLH-DSA).</p>
          <div class="row-3">
            <div class="field">
              <label>Sender</label>
              <input id="msg-sender" value="alice" />
            </div>
            <div class="field">
              <label>Recipient</label>
              <select id="msg-recipient">
                <option value="bob" selected>bob (node-b)</option>
                <option value="charlie">charlie (node-c)</option>
              </select>
            </div>
            <div class="field">
              <label>PQC Security Profile</label>
              <select id="msg-profile">
                <option value="v1" selected>track4/v1 (ML-KEM-768 + ML-DSA-65)</option>
                <option value="v2-paranoid">track4/v2-paranoid (ML-KEM-1024 + HQC-256 + SLH-DSA)</option>
              </select>
            </div>
          </div>
          <div class="field">
            <label>Confidential Payload Message</label>
            <input id="msg-input" value="Approve wire #8841: $25,000 Treasury -> Escrow-B" />
          </div>
          <div class="btn-row">
            <button class="act primary" onclick="sendTransfer()">Send PQC Envelope</button>
            <button class="act danger" onclick="apiCall('/api/sandbox/attack/replay', {}, 'msg-out', 'msg-verdict')">Simulate Replay Attack</button>
            <button class="act danger" onclick="apiCall('/api/sandbox/attack/recipient-swap', {}, 'msg-out', 'msg-verdict')">Simulate Recipient Swap</button>
          </div>
          <div class="btn-row">
            <button class="act warn" onclick="apiCall('/api/sandbox/attack/forward-secrecy', {}, 'msg-out', 'msg-verdict')">Verify Forward Secrecy</button>
            <button class="act warn" onclick="apiCall('/api/sandbox/attack/session-resumption', {}, 'msg-out', 'msg-verdict')">Test Session Hijack</button>
            <button class="act success" onclick="apiCall('/api/sandbox/attack/loss-reorder', {}, 'msg-out', 'msg-verdict')">Test Loss &amp; Reordering</button>
          </div>
        </div>

        <div class="card">
          <h2>Zero-Trust File Sharing Policy Guard (Max 20 MiB + Magic Bytes)</h2>
          <p class="sub">Validates extension allowlist, MIME match, file header magic bytes, and 20 MiB cap, then seals chunks through <code>SecureCryptoSystem</code>.</p>
          <div class="field">
            <label>Upload a Shared Media/Document File (Images, Audio, Video, PDF, TXT, CSV, JSON, MD &le; 20 MiB)</label>
            <input id="file-picker" type="file" />
          </div>
          <div class="btn-row">
            <button class="act primary" onclick="uploadAndVerifyFile()">Encrypt &amp; Verify Selected File</button>
            <button class="act success" onclick="apiCall('/api/sandbox/file-share/validate', {preset:'valid_png'}, 'msg-out', 'msg-verdict')">Preset: Valid PNG</button>
            <button class="act success" onclick="apiCall('/api/sandbox/file-share/validate', {preset:'valid_pdf'}, 'msg-out', 'msg-verdict')">Preset: Valid PDF</button>
          </div>
          <div class="btn-row">
            <button class="act danger" onclick="apiCall('/api/sandbox/file-share/validate', {preset:'spoofed_exe'}, 'msg-out', 'msg-verdict')">Attack: Spoofed EXE as .png</button>
            <button class="act danger" onclick="apiCall('/api/sandbox/file-share/validate', {preset:'disallowed_sh'}, 'msg-out', 'msg-verdict')">Attack: Disallowed .sh Script</button>
            <button class="act danger" onclick="apiCall('/api/sandbox/file-share/validate', {preset:'oversized_21mb'}, 'msg-out', 'msg-verdict')">Attack: &gt;20 MiB Payload</button>
          </div>
        </div>
      </div>

      <div class="card">
        <h2>Cryptographic Verification Inspector</h2>
        <div id="msg-verdict" class="verdict-box">
          <div>
            <div class="verdict-title">Ready for PQC Messaging or File Guard Check</div>
            <div class="verdict-sub">Select a profile, upload a file, or trigger an attack on the left.</div>
          </div>
        </div>
        <pre class="console" style="max-height:460px;" id="msg-out">Click any action on the left to execute live PQC operations, file magic-byte enforcement, or MITM attack checks.</pre>
      </div>
    </div>
  </div>

  <!-- TAB 4: KEY LIFECYCLE, DEVICES & AUTHORITY -->
  <div id="tab-lifecycle" class="tab-panel">
    <div class="grid-2" style="margin-bottom:16px;">
      <div class="card">
        <h2>Atomic Rotation, Revocation Broadcast &amp; Recovery</h2>
        <p class="sub">Rotate keys with configurable grace window, enforce hard cutoffs on all 3 nodes, revoke + measure propagation latency, or test WAL crash recovery &amp; HMAC-SHA3-512 backups.</p>
        <div class="field">
          <label>Grace Period Seconds (e.g. 3.0s for live testing)</label>
          <input id="grace-sec" type="number" step="0.5" min="0.5" max="30" value="3.0" />
        </div>
        <div class="btn-row">
          <button class="act primary" onclick="apiCall('/api/sandbox/lifecycle/rotate', {grace_seconds: parseFloat(document.getElementById('grace-sec').value || '3')}, 'life-out', 'life-verdict')">1. Rotate Key (Start Grace)</button>
          <button class="act warn" onclick="apiCall('/api/sandbox/lifecycle/test-old-key', {}, 'life-out', 'life-verdict')">2. Test Old Key (All 3 Nodes)</button>
          <button class="act danger" onclick="apiCall('/api/sandbox/lifecycle/revoke-and-reenroll', {mode: 'revoke'}, 'life-out', 'life-verdict')">3. Revoke Alice Key</button>
          <button class="act success" onclick="apiCall('/api/sandbox/lifecycle/revoke-and-reenroll', {mode: 'reenroll'}, 'life-out', 'life-verdict')">4. Re-Enroll New Device</button>
        </div>
        <div class="btn-row" style="margin-top:10px;">
          <button class="act warn" onclick="apiCall('/api/sandbox/resilience/crash-recovery', {}, 'life-out', 'life-verdict')">Simulate WAL Crash Recovery</button>
          <button class="act success" onclick="apiCall('/api/sandbox/resilience/backup', {tamper: false}, 'life-out', 'life-verdict')">Verify Signed Backup</button>
          <button class="act danger" onclick="apiCall('/api/sandbox/resilience/backup', {tamper: true}, 'life-out', 'life-verdict')">Corrupt 1 Byte &amp; Restore</button>
        </div>
      </div>

      <div class="card">
        <h2>1-Device Lock, Timezone Guard &amp; Authority Rollback</h2>
        <p class="sub">Enforces 1 device/user (<code>SingleDeviceRegistry</code>), rejects cross-timezone login jumps (<code>TimezoneMismatchError</code>), and auto-reverts suspicious admin console edits (<code>AuthorityMonitor</code>).</p>
        <div class="row-3">
          <div class="field">
            <label>User Identity</label>
            <input id="pol-user" value="alice" />
          </div>
          <div class="field">
            <label>Device ID</label>
            <input id="pol-dev" value="dev-alice-laptop-01" />
          </div>
          <div class="field">
            <label>Request Timezone</label>
            <select id="pol-tz">
              <option value="Asia/Kolkata" selected>Asia/Kolkata (Home)</option>
              <option value="America/New_York">America/New_York (Anomalous Jump)</option>
              <option value="Europe/London">Europe/London (Anomalous Jump)</option>
            </select>
          </div>
        </div>
        <div class="btn-row">
          <button class="act success" onclick="runDeviceTz('register_primary')">Bind Primary Device</button>
          <button class="act danger" onclick="runSecondDevice()">Attack: Add 2nd Device</button>
          <button class="act warn" onclick="runDeviceTz('timezone_check')">Test Timezone Access</button>
          <button class="act" onclick="runDeviceTz('reset')">Reset Policy DB</button>
        </div>
        <hr style="border:none;border-top:1px solid var(--border);margin:12px 0;" />
        <div class="row-2">
          <div class="field">
            <label>Suspicious Console Mutation Target</label>
            <select id="auth-action">
              <option value="DISABLE_AUDIT">DISABLE_AUDIT (audit_enabled=false)</option>
              <option value="DISABLE_TIMEZONE_CHECK">DISABLE_TIMEZONE_CHECK</option>
              <option value="MODIFY_SECURITY_POLICY">Raise Device Limit (max_devices=5)</option>
              <option value="BYPASS_POLICY">Raise File Limit (100 MB)</option>
            </select>
          </div>
          <div class="field">
            <label>Elevated Role</label>
            <select id="auth-role">
              <option value="admin" selected>admin (monitored)</option>
              <option value="security-operator">security-operator (monitored)</option>
            </select>
          </div>
        </div>
        <div class="btn-row">
          <button class="act primary" onclick="runAuthority('grant')">Grant Elevated Authority</button>
          <button class="act success" onclick="runAuthority('routine')">Routine Console Update</button>
          <button class="act danger" onclick="runAuthority('suspicious')">Attempt Suspicious Mutation</button>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <h2>Live Device, Authority &amp; Console Snapshot State</h2>
        <div id="id-status-box" style="margin-bottom:10px;"></div>
        <div id="policy-status-box"></div>
      </div>
      <div class="card">
        <h2>Lifecycle &amp; Policy Output</h2>
        <div id="life-verdict" class="verdict-box">
          <div>
            <div class="verdict-title">Ready for Key Lifecycle or Policy Enforcement Check</div>
            <div class="verdict-sub">Active keys, device locks, and authority snapshots update live.</div>
          </div>
        </div>
        <pre class="console" id="life-out">Trigger rotation, revocation, device/timezone checks, or suspicious console mutation tests.</pre>
      </div>
    </div>
  </div>

  <!-- TAB 5: AUDIT & TOOLKIT ADAPTER -->
  <div id="tab-audit" class="tab-panel">
    <div class="grid-2" style="margin-bottom:16px;">
      <div class="card">
        <h2>
          <span>Cryptographic Audit Hash Chain</span>
          <span id="audit-badge" class="badge ok">Checking...</span>
        </h2>
        <p class="sub">Continuous SHA-256 chaining (<code>H_i = SHA-256(H_{i-1} || canonical(E_i))</code>) with newline/JSON escape protection and uploaded log file verification.</p>
        <div class="btn-row" style="margin-bottom:10px;">
          <button class="act primary" onclick="apiCall('/api/sandbox/audit/tamper', {action: 'verify'}, 'audit-out', 'audit-verdict')">Verify Cluster Chain</button>
          <button class="act warn" onclick="apiCall('/api/sandbox/audit/injection', {}, 'audit-out', 'audit-verdict')">Test Newline/JSON Injection</button>
          <button class="act danger" onclick="apiCall('/api/sandbox/audit/tamper', {action: 'tamper'}, 'audit-out', 'audit-verdict')">Mutate 1 Byte</button>
          <button class="act success" onclick="apiCall('/api/sandbox/audit/tamper', {action: 'restore'}, 'audit-out', 'audit-verdict')">Restore Clean Chain</button>
        </div>
        <div class="field">
          <label>Verify an Exported Audit Log or Adapter State File (<code>*.log</code>, <code>*.jsonl</code>, <code>state.json</code>)</label>
          <div style="display:flex;gap:8px;align-items:center;">
            <input id="audit-file-picker" type="file" accept=".log,.jsonl,.json,.txt" />
            <button class="act primary" style="white-space:nowrap;" onclick="uploadAuditLogFile()">Check Log File</button>
          </div>
        </div>
        <div id="audit-verdict" class="verdict-box">
          <div>
            <div class="verdict-title">Hash Chain Ready</div>
            <div class="verdict-sub">Run verification, injection, tamper detection, or upload an audit log file.</div>
          </div>
        </div>
        <pre class="console" id="audit-out" style="max-height:170px;">Run chain verification, newline injection test, 1-byte mutation, or upload an audit log file.</pre>
      </div>

      <div class="card">
        <h2>Official Track-4 Adapter Runner (<code>track4_service.py</code>)</h2>
        <p class="sub">Executes real subprocess calls against <code>track4_service.py</code> using isolated <code>TRACK4_STATE_DIR</code> and live ML-KEM-768 + HMAC-SHA256 <code>protected_read</code> verification.</p>
        <div class="row-3">
          <div class="field"><label>Actor</label><input id="adp-actor" value="maya" /></div>
          <div class="field"><label>Asset ID</label><input id="adp-asset" value="brief" /></div>
          <div class="field"><label>Request ID</label><input id="adp-reqid" value="req-gui-01" /></div>
        </div>
        <div class="field"><label>Asset Content Body</label><input id="adp-body" value="Classified Track-4 Zero-Trust Brief" /></div>
        <div class="btn-row">
          <button class="act primary" onclick="runAdapter('full_suite')">Run Full Lost-Device + ML-KEM-768 Suite</button>
          <button class="act success" onclick="runAdapter('single', 'setup')">Setup</button>
          <button class="act" onclick="runAdapter('single', 'read')">Read</button>
          <button class="act purple" onclick="runAdapter('single', 'protected_read')">Protected Read</button>
          <button class="act danger" onclick="runAdapter('single', 'revoke')">Revoke</button>
          <button class="act warn" onclick="runAdapter('single', 'audit')">Audit</button>
        </div>
        <pre class="console" id="adapter-out" style="margin-top:10px;max-height:205px;">Click "Run Full Lost-Device + ML-KEM-768 Suite" or step through setup -&gt; read -&gt; protected_read -&gt; revoke -&gt; audit.</pre>
      </div>
    </div>

    <div class="card">
      <h2>Live Forensic Audit Chain Records</h2>
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

  <!-- TAB 6: DETECTOR & PRACTICE ANALYZER -->
  <div id="tab-detector" class="tab-panel">
    <div class="grid-2" style="margin-bottom:16px;">
      <div class="card">
        <h2>Explainable Rules, Lateral Movement DAG &amp; Clock Skew</h2>
        <p class="sub">100% deterministic graph &amp; rule engine (zero AI/ML). Flags privilege abuse, unauthorized service hops, and out-of-order timing skew.</p>
        <div class="btn-row">
          <button class="act danger" onclick="apiCall('/api/sandbox/detector/lateral-movement', {}, 'det-out', 'det-verdict')">Lateral Hop (audit &rarr; node-c)</button>
          <button class="act danger" onclick="apiCall('/api/sandbox/detector/privilege-escalation', {}, 'det-out', 'det-verdict')">Privilege Gain (guest &rarr; admin)</button>
          <button class="act warn" onclick="apiCall('/api/sandbox/detector/clock-skew', {}, 'det-out', 'det-verdict')">Clock Skew (&plusmn;2000ms)</button>
          <button class="act primary" onclick="apiCall('/api/sandbox/detector/eval-metrics', {}, 'det-out', 'det-verdict')">Benchmark (550 Events)</button>
        </div>
        <div class="dag-wrap">
          <div class="mono" style="color:var(--muted);margin-bottom:6px;font-size:11px;">MICROSERVICE ACCESS TOPOLOGY DAG (GREEN = ALLOWED, RED = LATERAL BLOCKED)</div>
          <svg viewBox="0 0 640 165" width="100%" height="150" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <marker id="arr-ok" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#10b981"/></marker>
              <marker id="arr-bad" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#ef4444"/></marker>
            </defs>
            <line x1="120" y1="45" x2="255" y2="45" stroke="#10b981" stroke-width="2" marker-end="url(#arr-ok)"/>
            <line x1="120" y1="55" x2="255" y2="120" stroke="#10b981" stroke-width="2" marker-end="url(#arr-ok)"/>
            <line x1="365" y1="45" x2="495" y2="45" stroke="#10b981" stroke-width="2" marker-end="url(#arr-ok)"/>
            <line x1="365" y1="120" x2="495" y2="120" stroke="#10b981" stroke-width="2" marker-end="url(#arr-ok)"/>
            <line x1="495" y1="115" x2="370" y2="55" stroke="#ef4444" stroke-width="2.5" stroke-dasharray="5,4" marker-end="url(#arr-bad)"/>
            <text x="415" y="96" fill="#fca5a5" font-size="10" font-family="monospace">BLOCKED DAG EDGE</text>

            <rect x="16" y="25" width="104" height="40" rx="8" fill="#151f31" stroke="#38bdf8"/>
            <text x="68" y="49" fill="#e2e8f0" text-anchor="middle" font-size="12" font-family="monospace">api-gateway</text>

            <rect x="260" y="25" width="105" height="40" rx="8" fill="#151f31" stroke="#10b981"/>
            <text x="312" y="49" fill="#e2e8f0" text-anchor="middle" font-size="12" font-family="monospace">node-c</text>

            <rect x="260" y="100" width="105" height="40" rx="8" fill="#151f31" stroke="#10b981"/>
            <text x="312" y="124" fill="#e2e8f0" text-anchor="middle" font-size="12" font-family="monospace">auth-service</text>

            <rect x="500" y="25" width="120" height="40" rx="8" fill="#151f31" stroke="#a78bfa"/>
            <text x="560" y="49" fill="#e2e8f0" text-anchor="middle" font-size="12" font-family="monospace">detector</text>

            <rect x="500" y="100" width="120" height="40" rx="8" fill="#151f31" stroke="#f59e0b"/>
            <text x="560" y="124" fill="#fcd34d" text-anchor="middle" font-size="12" font-family="monospace">audit-service</text>
          </svg>
        </div>
        <div id="eval-metrics-box" style="margin-top:12px;"></div>
        <div id="det-verdict" class="verdict-box" style="margin-top:10px;">
          <div>
            <div class="verdict-title">Detector Ready</div>
            <div class="verdict-sub">Run a rule trigger or the 550-event benchmark.</div>
          </div>
        </div>
        <pre class="console" id="det-out" style="max-height:170px;">Run lateral movement, privilege escalation, clock-skew ordering, or F1/MTTA benchmark.</pre>
      </div>

      <div class="card">
        <h2>Live Explainable Alerts Feed</h2>
        <div id="alerts-feed" style="max-height:560px;overflow:auto;"></div>
      </div>
    </div>

    <div class="card">
      <h2>
        <span>Event Timeline &amp; Change-Approval Triage (<code>events.csv</code> + <code>approvals.json</code> + <code>labels.csv</code>)</span>
        <span id="practice-badge" class="badge info">Not run yet</span>
      </h2>
      <p class="sub">Upload test files directly (<code>events.csv</code>, <code>approvals.json</code>, optional <code>labels.csv</code>) or analyze the Track-4 practice set.</p>
      <div class="row-3" style="margin-bottom:10px;">
        <div class="field"><label>Events CSV File (<code>events.csv</code>)</label><input id="prac-events-file" type="file" accept=".csv,.txt" /></div>
        <div class="field"><label>Approvals JSON File (<code>approvals.json</code>)</label><input id="prac-approvals-file" type="file" accept=".json" /></div>
        <div class="field"><label>Expected Labels CSV (optional <code>labels.csv</code>)</label><input id="prac-labels-file" type="file" accept=".csv,.txt" /></div>
      </div>
      <div class="btn-row" style="margin-bottom:10px;">
        <button class="act success" onclick="analyzeUploadedPracticeFiles()">Check Uploaded Practice Files</button>
        <button class="act primary" onclick="runPracticeAnalysis(true)">Analyze Built-in / Local Practice Dataset</button>
        <button class="act" onclick="toggleCustomCsv()">Toggle Paste Textareas</button>
      </div>
      <div id="custom-csv-box" style="display:none;margin-bottom:12px;">
        <div class="grid-2">
          <div class="field">
            <label>Paste Events CSV</label>
            <textarea id="custom-events-csv" placeholder="event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,source_service,target_service,action,role_before,role_after,outcome,approval_id,session_id,correlation_id"></textarea>
          </div>
          <div class="field">
            <label>Paste approvals.json</label>
            <textarea id="custom-approvals-json">{"changes": []}</textarea>
          </div>
        </div>
        <button class="act success" onclick="runPracticeAnalysis(false)">Analyze Pasted Events &amp; Approvals</button>
      </div>
      <div id="practice-summary" style="margin-bottom:10px;"></div>
      <div style="overflow-x:auto;max-height:360px;">
        <table>
          <thead>
            <tr><th>Event</th><th>Actor</th><th>Service Edge</th><th>Corrected UTC</th><th>Offset</th><th>Classification</th><th>Explanation</th></tr>
          </thead>
          <tbody id="practice-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 7: HOW TO USE & THREAT MODEL -->
  <div id="tab-threat" class="tab-panel">
    <div class="card" style="margin-bottom:16px;">
      <h2>How to Use Trust, But Verify (GUI + CLI Quick Reference)</h2>
      <p class="sub">Every control in this web console maps directly to real cryptographic, identity, audit, and detector primitives verifiable from the command line.</p>
      <div class="grid-2">
        <div>
          <h3>CLI Verification Commands (run inside <code>.venv</code>)</h3>
          <div class="cmd-line"><code>python -m src.cli demo-replay &amp;&amp; python -m src.cli demo-forward-secrecy</code><button class="act" onclick="copyText('python -m src.cli demo-replay && python -m src.cli demo-forward-secrecy')">Copy</button></div>
          <div class="cmd-line"><code>python -m src.cli demo-chunked-loss &amp;&amp; python -m src.cli demo-resumption-binding</code><button class="act" onclick="copyText('python -m src.cli demo-chunked-loss && python -m src.cli demo-resumption-binding')">Copy</button></div>
          <div class="cmd-line"><code>python -m src.cli verify-logs &amp;&amp; python -m src.cli doc-check</code><button class="act" onclick="copyText('python -m src.cli verify-logs && python -m src.cli doc-check')">Copy</button></div>
          <div class="cmd-line"><code>python ../Track-4-Toolkit/validate.py --entry ./track4_service.py</code><button class="act" onclick="copyText('python ../Track-4-Toolkit/validate.py --entry ./track4_service.py')">Copy</button></div>
          <div class="cmd-line"><code>pytest tests/ -v</code><button class="act" onclick="copyText('pytest tests/ -v')">Copy</button></div>
        </div>
        <div>
          <h3>Interactive GUI Walkthrough</h3>
          <ul style="color:var(--muted);padding-left:18px;font-size:12.5px;line-height:1.65;margin-top:4px;">
            <li><strong>Step 1 (Tab 2 — Test Files):</strong> Drag &amp; drop <code>events.csv</code> + <code>approvals.json</code> + <code>labels.csv</code>, <code>*.log</code> files, or repo <code>tests/test_*.py</code> files — or run pytest / Track-4-Toolkit directly.</li>
            <li><strong>Step 2 (Tab 3 — PQC &amp; Files):</strong> Send messages under <code>v1</code> or <code>v2-paranoid</code>, upload media/docs (&le; 20 MiB), and test replay &amp; swap rejection.</li>
            <li><strong>Step 3 (Tab 4 — Keys &amp; Authority):</strong> Rotate/revoke keys across 3 nodes, test 1-device/timezone limits, and watch <code>AuthorityMonitor</code> revert suspicious mutations.</li>
            <li><strong>Step 4 (Tab 5 — Audit &amp; Adapter):</strong> Verify or tamper hash chains, upload an exported <code>audit.log</code>, and run <code>track4_service.py</code> ML-KEM-768 <code>protected_read</code> checks.</li>
            <li><strong>Step 5 (Tab 6 — Detector):</strong> Inspect lateral movement DAGs, benchmark F1/MTTA metrics, and upload practice log CSVs directly.</li>
          </ul>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <h2>1. Protected Assets &amp; Adversary Model</h2>
        <div class="kv"><span>In-Flight Payloads</span><span>AES-256-GCM + Recipient Binding AAD</span></div>
        <div class="kv"><span>Node Identity Keys</span><span>NIST ML-DSA-65 / Dual ML-DSA-87 + SLH-DSA</span></div>
        <div class="kv"><span>Session Secrets</span><span>Ephemeral X25519 + ML-KEM-768 (+ HQC-256 in v2)</span></div>
        <div class="kv"><span>File Shares &amp; Devices</span><span>20 MiB + Magic Bytes + 1 Device/User + Timezone</span></div>
        <div class="kv"><span>Key State &amp; Backups</span><span>Fsynced WAL + HMAC-SHA3-512 snapshots</span></div>
        <div class="kv"><span>Audit &amp; Console Config</span><span>SHA-256 hash chain + pre-change rollback snapshot</span></div>
        <hr style="border:none;border-top:1px solid var(--border);margin:12px 0;" />
        <h3>Threat Actors Addressed</h3>
        <ul style="color:var(--muted);padding-left:18px;font-size:12.5px;">
          <li><strong>Harvest-Now-Decrypt-Later (HNDL):</strong> Hybrid + multi-family PQC KEM prevents retroactive decryption.</li>
          <li><strong>Network MITM:</strong> Replay cache, sequence monotonicity, chunked AAD, and recipient binding.</li>
          <li><strong>Hijacked / Insider Admin:</strong> Timezone anomaly lock, 1-device cap, and <code>AuthorityMonitor</code> config rollback.</li>
          <li><strong>Log-Injection Attacker:</strong> Newline/JSON escape sanitization + continuous SHA-256 chain verification.</li>
        </ul>
      </div>
      <div class="card">
        <h2>2. Trust Assumptions &amp; Honest System Limits</h2>
        <ul style="color:var(--muted);padding-left:18px;font-size:12.5px;line-height:1.65;">
          <li><strong>Zero AI/ML Hallucination:</strong> Detection relies purely on O(1) DAG edge checks and deterministic rules; zero model drift or training data bias.</li>
          <li><strong>Clock-Skew Boundary (&plusmn;2000ms):</strong> Events within &plusmn;2000ms are buffered and ordered; extreme skew is preserved and flagged.</li>
          <li><strong>SQLite &amp; File Locks:</strong> Adapter and policy databases use local <code>fcntl</code> / SQLite WAL locks; single-host persistence requires durable storage (<code>TRACK4_STATE_DIR</code>) in production.</li>
          <li><strong>Python Heap Zeroization:</strong> Secret key wiping uses best-effort mutable <code>bytearray</code> clearing and reference dropping; production deployment should pair with KMS/HSM sealing.</li>
          <li><strong>Metadata Visibility:</strong> Envelope routing fields (<span class="mono">sender_id</span>, <span class="mono">recipient_id</span>) remain visible for recipient-binding checks.</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<script>
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function copyText(txt) {
  if (navigator.clipboard) navigator.clipboard.writeText(txt);
}

function switchTab(id) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  const panel = document.getElementById('tab-' + id);
  const btn = document.querySelector(`.tab-btn[data-tab="${id}"]`);
  if (panel) panel.classList.add('active');
  if (btn) btn.classList.add('active');
}

function setVerdict(boxId, data) {
  const box = document.getElementById(boxId);
  if (!box || !data) return;
  let cls = 'verdict-box';
  let title = 'Completed';
  let sub = '';
  if (data.blocked) {
    cls += ' blocked';
    title = 'BLOCKED (Security Control Enforced)';
    sub = data.detail || data.error_type || data.reason || 'Attack or policy violation denied';
  } else if (data.ok === false || data.is_valid === false) {
    cls += ' bad';
    title = 'Check Reported Failure';
    sub = data.first_error || data.detail || 'Inspect details below';
  } else {
    cls += ' ok';
    title = data.allowed === true ? 'ALLOWED &amp; VERIFIED' : 'PASSED / VERIFIED';
    const parts = [];
    if (data.profile) parts.push('suite=' + data.profile);
    if (data.latency_ms !== undefined) parts.push('latency=' + data.latency_ms + 'ms');
    if (data.propagation_ms !== undefined) parts.push('propagation=' + data.propagation_ms + 'ms');
    if (data.sha256) parts.push('sha256=' + data.sha256.slice(0, 14) + '...');
    if (data.phase) parts.push('phase=' + data.phase);
    if (data.total_records !== undefined) parts.push('records=' + data.total_records);
    sub = parts.join(' | ') || (data.detail || 'Operation succeeded and audit logged');
  }
  box.className = cls;
  box.innerHTML = '<div><div class="verdict-title">' + title + '</div><div class="verdict-sub">' + esc(sub) + '</div></div>';
}

function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

async function apiCall(url, body, outId, verdictId) {
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
    if (verdictId) setVerdict(verdictId, data);
    await refreshState();
    return data;
  } catch (err) {
    if (out) out.textContent = 'Error: ' + err;
  }
}

// ---------------------------------------------------------------------------
// Universal Test Files & Pytest Runner
// ---------------------------------------------------------------------------
let queuedBundleFiles = [];

const dz = document.getElementById('bundle-dropzone');
if (dz) {
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
  dz.addEventListener('drop', e => {
    e.preventDefault();
    dz.classList.remove('drag');
    if (e.dataTransfer && e.dataTransfer.files) {
      handleBundleFiles(e.dataTransfer.files);
    }
  });
}

function handleBundleFiles(fileList) {
  queuedBundleFiles = Array.from(fileList || []);
  document.getElementById('bundle-chips').innerHTML = queuedBundleFiles.map(
    f => `<span class="file-chip">${esc(f.name)} (${f.size} B)</span>`
  ).join('');
  if (queuedBundleFiles.length > 0) {
    checkSelectedBundle();
  }
}

function clearBundleFiles() {
  queuedBundleFiles = [];
  document.getElementById('bundle-picker').value = '';
  document.getElementById('bundle-chips').innerHTML = '';
}

async function checkSelectedBundle() {
  if (!queuedBundleFiles.length) {
    setVerdict('bundle-verdict', {ok: false, detail: 'Select or drop one or more test files first.'});
    return;
  }
  const badge = document.getElementById('bundle-status-badge');
  badge.className = 'badge warn';
  badge.textContent = `Checking ${queuedBundleFiles.length} file(s)...`;
  document.getElementById('bundle-raw-out').textContent = 'Reading and verifying uploaded files...';

  const items = [];
  for (const file of queuedBundleFiles) {
    const buf = await file.arrayBuffer();
    items.push({
      filename: file.name,
      mime_type: file.type || null,
      content_b64: bytesToB64(new Uint8Array(buf))
    });
  }
  const res = await fetch('/api/sandbox/files/check-bundle', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({files: items})
  });
  const data = await res.json();
  document.getElementById('bundle-raw-out').textContent = JSON.stringify(data, null, 2);

  const s = data.summary || {total_files: 0, passed: 0, blocked_or_failed: 0};
  badge.className = 'badge ' + (s.blocked_or_failed === 0 ? 'ok' : 'warn');
  badge.textContent = `${s.passed}/${s.total_files} Verified`;
  setVerdict('bundle-verdict', {
    ok: s.blocked_or_failed === 0,
    detail: `Checked ${s.total_files} file(s): ${s.passed} passed, ${s.blocked_or_failed} blocked or failed`
  });

  document.getElementById('bundle-results-wrap').innerHTML = `
    <table>
      <thead><tr><th>File</th><th>Verification Check</th><th>Status</th><th>Summary</th></tr></thead>
      <tbody>
        ${(data.results || []).map(r => `
          <tr>
            <td class="mono">${esc(r.filename)}</td>
            <td>${esc(r.check_type)}</td>
            <td><span class="badge ${r.status === 'PASS' ? 'ok' : (r.status === 'BLOCKED' ? 'warn' : 'bad')}">${esc(r.status)}</span></td>
            <td>${esc(r.summary)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  if (data.practice_triage && data.practice_triage.events) {
    renderPracticeTableInto('bundle-triage-wrap', data.practice_triage);
  } else {
    document.getElementById('bundle-triage-wrap').innerHTML = '';
  }
  await refreshState();
}

async function loadRepoTests() {
  try {
    const res = await fetch('/api/sandbox/tests/list');
    const data = await res.json();
    const files = data.test_files || [];
    document.getElementById('repo-tests-meta').textContent = `${files.length} suites | toolkit=${data.toolkit_available ? 'found' : 'absent'}`;
    document.getElementById('repo-tests-list').innerHTML = files.map(t => `
      <div class="test-item">
        <label><input type="checkbox" class="repo-test-chk" value="${esc(t.name)}" /> <span>tests/${esc(t.name)}</span></label>
        <span style="color:var(--muted);">${t.size_bytes} B</span>
      </div>
    `).join('');
  } catch (e) {
    document.getElementById('repo-tests-list').textContent = 'Failed to load tests list';
  }
}

function toggleAllTests(checked) {
  document.querySelectorAll('.repo-test-chk').forEach(cb => { cb.checked = checked; });
}

async function executeRepoTestRun(payload) {
  const badge = document.getElementById('bundle-status-badge');
  badge.className = 'badge warn';
  badge.textContent = 'Running tests...';
  document.getElementById('bundle-raw-out').textContent = 'Executing test runner...';
  document.getElementById('bundle-results-wrap').innerHTML = '';
  document.getElementById('bundle-triage-wrap').innerHTML = '';

  const res = await fetch('/api/sandbox/tests/run', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
  });
  const data = await res.json();
  let txt = '';
  if (data.pytest) txt += `=== PYTEST ===\\n${data.pytest.output}\\n\\n`;
  if (data.toolkit_validator) txt += `=== TRACK-4-TOOLKIT VALIDATOR ===\\n${data.toolkit_validator.output}`;
  if (!txt) txt = JSON.stringify(data, null, 2);
  document.getElementById('bundle-raw-out').textContent = txt;

  badge.className = 'badge ' + (data.ok ? 'ok' : 'bad');
  const pCounts = data.pytest ? data.pytest.counts : null;
  badge.textContent = data.ok ? `PASS (${data.duration_ms}ms)` : `FAIL (${data.duration_ms}ms)`;
  const summaryParts = [];
  if (pCounts) summaryParts.push(`pytest: ${pCounts.passed} passed, ${pCounts.failed} failed`);
  if (data.toolkit_validator) summaryParts.push(`Track-4-Toolkit: ${data.toolkit_validator.passed ? 'PASS' : 'FAIL'}`);
  setVerdict('bundle-verdict', {ok: data.ok, detail: summaryParts.join(' | ') || data.detail});
  await refreshState();
}

async function runSelectedTests(includeToolkitOnly) {
  const selected = Array.from(document.querySelectorAll('.repo-test-chk:checked')).map(c => c.value);
  if (includeToolkitOnly) {
    return executeRepoTestRun({test_files: [], run_pytest: false, include_toolkit_validator: true});
  }
  if (!selected.length) {
    setVerdict('bundle-verdict', {ok: false, detail: 'Check one or more test files on the right, or click Run Full Pytest Suite.'});
    return;
  }
  return executeRepoTestRun({test_files: selected, run_pytest: true, include_toolkit_validator: false});
}

async function runAllPytestSuites() {
  return executeRepoTestRun({test_files: [], run_pytest: true, include_toolkit_validator: true});
}

// ---------------------------------------------------------------------------
// Tab 3..6 Helpers
// ---------------------------------------------------------------------------
async function sendTransfer() {
  const sender = document.getElementById('msg-sender').value || 'alice';
  const recipient = document.getElementById('msg-recipient').value || 'bob';
  const profile = document.getElementById('msg-profile').value || 'v1';
  const message = document.getElementById('msg-input').value || '';
  return apiCall('/api/sandbox/pqc-transfer', {sender, recipient, profile, message}, 'msg-out', 'msg-verdict');
}

async function uploadAndVerifyFile() {
  const inp = document.getElementById('file-picker');
  const file = inp && inp.files && inp.files[0];
  if (!file) {
    setVerdict('msg-verdict', {ok: false, detail: 'Choose a file first or click one of the Preset buttons.'});
    return;
  }
  if (file.size > 22 * 1024 * 1024) {
    setVerdict('msg-verdict', {ok: true, blocked: true, detail: `Browser pre-check: ${file.name} is ${(file.size / (1024*1024)).toFixed(2)} MiB (>20 MiB limit)`});
    document.getElementById('msg-out').textContent = JSON.stringify({blocked: true, filename: file.name, size_bytes: file.size, max_bytes: 20 * 1024 * 1024}, null, 2);
    return;
  }
  const buf = await file.arrayBuffer();
  return apiCall('/api/sandbox/file-share/validate', {
    filename: file.name,
    mime_type: file.type || null,
    content_b64: bytesToB64(new Uint8Array(buf))
  }, 'msg-out', 'msg-verdict');
}

async function uploadAuditLogFile() {
  const inp = document.getElementById('audit-file-picker');
  const file = inp && inp.files && inp.files[0];
  if (!file) {
    setVerdict('audit-verdict', {ok: false, detail: 'Choose an audit.log, .jsonl, or state.json file first.'});
    return;
  }
  const content = await file.text();
  return apiCall('/api/sandbox/audit/verify-file', {filename: file.name, content}, 'audit-out', 'audit-verdict');
}

async function runDeviceTz(mode) {
  const user_id = document.getElementById('pol-user').value || 'alice';
  const device_id = document.getElementById('pol-dev').value || 'dev-alice-laptop-01';
  const timezone = document.getElementById('pol-tz').value || 'Asia/Kolkata';
  return apiCall('/api/sandbox/policy/device-timezone', {mode, user_id, device_id, timezone}, 'life-out', 'life-verdict');
}

async function runSecondDevice() {
  const user_id = document.getElementById('pol-user').value || 'alice';
  const timezone = document.getElementById('pol-tz').value || 'Asia/Kolkata';
  return apiCall('/api/sandbox/policy/device-timezone', {mode: 'second_device', user_id, device_id: 'dev-rogue-secondary-02', timezone}, 'life-out', 'life-verdict');
}

async function runAuthority(mode) {
  const user_id = document.getElementById('pol-user').value || 'alice';
  const role = document.getElementById('auth-role').value || 'admin';
  const action = document.getElementById('auth-action').value || 'DISABLE_AUDIT';
  return apiCall('/api/sandbox/authority/console-action', {mode, user_id, role, action}, 'life-out', 'life-verdict');
}

async function runAdapter(mode, op) {
  const actor = document.getElementById('adp-actor').value || 'maya';
  const asset = document.getElementById('adp-asset').value || 'brief';
  const body = document.getElementById('adp-body').value || 'Brief';
  const request_id = document.getElementById('adp-reqid').value || 'req-gui-01';
  const out = document.getElementById('adapter-out');
  if (out) out.textContent = 'Running track4_service.py (' + (op || mode) + ') ...';
  return apiCall('/api/sandbox/toolkit/adapter-run', {mode, op, actor, asset, body, request_id}, 'adapter-out', null);
}

function toggleCustomCsv() {
  const box = document.getElementById('custom-csv-box');
  box.style.display = box.style.display === 'none' ? 'block' : 'none';
}

function renderPracticeTableInto(containerId, data) {
  const fs = data.findings_summary || {};
  document.getElementById(containerId).innerHTML = `
    <div class="grid-4" style="margin-bottom:8px;">
      <div class="chk-item fail"><span class="mono">Unapproved Escalations</span><strong>${esc((fs.unexpected_role_changes || []).join(', ') || '0')}</strong></div>
      <div class="chk-item fail"><span class="mono">Lateral Chains</span><strong>${esc((fs.lateral_movement_chains || []).join(', ') || '0')}</strong></div>
      <div class="chk-item"><span class="mono">Clock Skew Adjusted</span><strong>${esc((fs.clock_skew_events || []).join(', ') || '0')}</strong></div>
      <div class="chk-item pass"><span class="mono">Label Agreement</span><strong>${esc(data.label_matches)}</strong></div>
    </div>
    <table>
      <thead><tr><th>Event</th><th>Actor</th><th>Service Edge</th><th>Corrected UTC</th><th>Offset</th><th>Classification</th><th>Explanation</th></tr></thead>
      <tbody>
        ${(data.events || []).map(ev => {
          const cls = ev.classification || 'routine';
          const bCls = cls.includes('unexpected') || cls.includes('lateral') || cls.includes('review') ? 'bad'
            : cls.includes('approved') ? 'ok'
            : cls.includes('clock') || cls.includes('delayed') || cls.includes('isolated') ? 'warn' : 'info';
          return `
            <tr>
              <td class="mono">${esc(ev.event_id)}</td>
              <td class="mono">${esc(ev.actor)}</td>
              <td class="mono">${esc(ev.edge)}</td>
              <td class="mono">${esc(ev.corrected_utc)}</td>
              <td class="mono">${esc(ev.offset_ms)}ms</td>
              <td><span class="badge ${bCls}">${esc(cls)}</span></td>
              <td>${esc(ev.explanation)}</td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
}

async function analyzeUploadedPracticeFiles() {
  const evFile = document.getElementById('prac-events-file').files[0];
  const appFile = document.getElementById('prac-approvals-file').files[0];
  const lblFile = document.getElementById('prac-labels-file').files[0];
  const badge = document.getElementById('practice-badge');
  if (!evFile) {
    badge.className = 'badge warn';
    badge.textContent = 'Select an events.csv file first';
    return;
  }
  const events_csv = await evFile.text();
  const approvals_json = appFile ? await appFile.text() : '{"changes": []}';
  const labels_csv = lblFile ? await lblFile.text() : null;
  return _runPracticePayload({events_csv, approvals_json, labels_csv, use_sample: false});
}

async function runPracticeAnalysis(useSample) {
  const body = useSample ? {use_sample: true} : {
    use_sample: false,
    events_csv: document.getElementById('custom-events-csv').value,
    approvals_json: document.getElementById('custom-approvals-json').value
  };
  return _runPracticePayload(body);
}

async function _runPracticePayload(body) {
  const badge = document.getElementById('practice-badge');
  badge.textContent = 'Analyzing...';
  const res = await fetch('/api/sandbox/detector/practice-events', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!data.ok) {
    badge.className = 'badge bad';
    badge.textContent = data.detail || 'Error';
    return;
  }
  badge.className = 'badge ok';
  badge.textContent = `${data.total_events} events (${data.dataset_source})` + (data.label_matches !== 'no labels.csv provided' ? ` | Labels: ${data.label_matches}` : '');

  const fs = data.findings_summary || {};
  document.getElementById('practice-summary').innerHTML = `
    <div class="grid-4">
      <div class="chk-item fail"><span class="mono">Unapproved Role Escalations</span><strong>${esc((fs.unexpected_role_changes || []).join(', ') || '0')}</strong></div>
      <div class="chk-item fail"><span class="mono">Lateral Movement Chain</span><strong>${esc((fs.lateral_movement_chains || []).join(', ') || '0')}</strong></div>
      <div class="chk-item"><span class="mono">Clock Skew Adjusted</span><strong>${esc((fs.clock_skew_events || []).join(', ') || '0')}</strong></div>
      <div class="chk-item"><span class="mono">Out-of-Order Delivery</span><strong>${esc((fs.delayed_out_of_order || []).join(', ') || '0')}</strong></div>
    </div>
  `;

  document.getElementById('practice-tbody').innerHTML = (data.events || []).map(ev => {
    const cls = ev.classification || 'routine';
    const bCls = cls.includes('unexpected') || cls.includes('lateral') || cls.includes('review') ? 'bad'
      : cls.includes('approved') ? 'ok'
      : cls.includes('clock') || cls.includes('delayed') || cls.includes('isolated') ? 'warn' : 'info';
    return `
      <tr>
        <td class="mono">${esc(ev.event_id)}</td>
        <td class="mono">${esc(ev.actor)}</td>
        <td class="mono">${esc(ev.edge)}</td>
        <td class="mono">${esc(ev.corrected_utc)}</td>
        <td class="mono">${esc(ev.offset_ms)}ms</td>
        <td><span class="badge ${bCls}">${esc(cls)}</span></td>
        <td>${esc(ev.explanation)}</td>
      </tr>
    `;
  }).join('');
  await refreshState();
}

async function refreshState() {
  try {
    const res = await fetch('/api/sandbox/state');
    const s = await res.json();

    document.getElementById('uptime-lbl').textContent = 'uptime: ' + s.uptime_seconds + 's';
    const prov = s.crypto.provider || 'pqcrypto';
    document.getElementById('hdr-pqc').textContent = `PQC: ${s.crypto.kem_algorithm} + ${s.crypto.sig_algorithm} (${prov})`;

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

    const ps = s.policy_state || {};
    const cs = ps.console_state || {};
    document.getElementById('hdr-policy').textContent = `${ps.max_file_size_mb || 20} MiB | ${ps.max_devices_per_user || 1} Device/User`;
    document.getElementById('policy-overview-strip').innerHTML = `
      <div class="chk-item pass"><span class="mono">Max Shared File</span><strong>${esc(ps.max_file_size_mb || 20)} MiB + Magic Bytes</strong></div>
      <div class="chk-item pass"><span class="mono">Device Lock Policy</span><strong>Strictly ${esc(ps.max_devices_per_user || 1)} Active / User</strong></div>
      <div class="chk-item pass"><span class="mono">Timezone Guard</span><strong>${cs.timezone_check_enabled !== false ? 'ENFORCED' : 'OFF'}</strong></div>
      <div class="chk-item pass"><span class="mono">Console Audit Lock</span><strong>${cs.audit_enabled !== false ? 'LOCKED ON' : 'OFF'} (${esc((ps.console_state_hash || '').slice(0,10))}...)</strong></div>
    `;

    document.getElementById('nodes-grid').innerHTML = s.nodes.map(n => `
      <div class="card">
        <h3><span>${esc(n.node_id)}</span><span class="badge ${n.active_key_id ? 'ok' : 'bad'}">${n.active_key_id ? 'ACTIVE v' + esc(n.active_version) : 'KEY REVOKED'}</span></h3>
        <div class="kv"><span>Active Key</span><span class="mono">${esc(n.active_key_id || 'NONE')}</span></div>
        <div class="kv"><span>Grace Keys</span><span class="mono">${esc(n.grace_keys_count)} ${n.remaining_grace_sec > 0 ? '(' + esc(n.remaining_grace_sec) + 's left)' : ''}</span></div>
        <div class="kv"><span>Revoked / Expired</span><span class="mono">${esc(n.revoked_count)} / ${esc(n.expired_count)}</span></div>
      </div>
    `).join('');

    document.getElementById('checklist-grid').innerHTML = s.checklist.map(c => `
      <div class="chk-item ${esc(c.status)}">
        <div class="chk-top">
          <span>${esc(c.label)}</span>
          <span class="badge ${c.status === 'pass' ? 'ok' : 'warn'}">${c.status === 'pass' ? 'PASS' : 'PENDING'}</span>
        </div>
        <div class="chk-sum">${esc(c.summary)}</div>
      </div>
    `).join('');

    const al = s.identities.alice;
    const bo = s.identities.bob;
    document.getElementById('id-status-box').innerHTML = `
      <div class="kv"><span>Alice (${esc(al.device_id)})</span><span class="badge ${al.status === 'active' ? 'ok' : 'bad'}">${esc(al.status.toUpperCase())} (${esc(al.active_key_id || al.revoked_key_id)})</span></div>
      <div class="kv"><span>Bob (${esc(bo.device_id)})</span><span class="badge ok">ACTIVE (${esc(bo.active_key_id)})</span></div>
      <div class="kv"><span>Last Revocation Latency</span><span class="mono">${s.revocation_propagation_ms !== null ? esc(s.revocation_propagation_ms) + ' ms' : 'Not yet measured'}</span></div>
    `;

    const devRows = (ps.devices || []).map(d => `<div class="kv"><span>${esc(d.user_id)} / ${esc(d.device_id)}</span><span class="badge ${d.status === 'active' ? 'ok' : 'bad'}">${esc(d.status)} @ ${esc(d.home_timezone)}</span></div>`).join('');
    const authRows = (ps.authorities || []).map(a => `<div class="kv"><span>Authority: ${esc(a.user_id)} (${esc(a.role)})</span><span class="badge ${a.status === 'active' && !a.has_active_threat ? 'ok' : 'bad'}">${esc(a.status.toUpperCase())}${a.has_active_threat ? ' [THREAT: ' + esc(a.last_threat_case) + ']' : ''}</span></div>`).join('');
    document.getElementById('policy-status-box').innerHTML = `
      <div class="kv"><span>Console Protected Digest</span><span class="mono">${esc((ps.console_state_hash || '').slice(0, 20))}...</span></div>
      <div class="kv"><span>Console audit_enabled / tz_check</span><span class="badge ok">${esc(cs.audit_enabled)} / ${esc(cs.timezone_check_enabled)}</span></div>
      ${devRows}
      ${authRows}
    `;

    document.getElementById('audit-tbody').innerHTML = (s.audit.recent_entries || []).map(r => `
      <tr>
        <td class="mono">${esc(r.sequence ?? '-')}</td>
        <td class="mono">${esc(r.service || '-')}</td>
        <td class="mono">${esc(r.action || '-')}</td>
        <td class="mono">${esc((r.subject || '-').slice(0, 42))}</td>
        <td><span class="badge ${r.status === 'SUCCESS' ? 'ok' : 'bad'}">${esc(r.status || '-')}</span></td>
        <td class="hash-pill">${esc((r.entry_hash || '').slice(0, 18))}...</td>
      </tr>
    `).join('');

    const alerts = s.alerts || [];
    document.getElementById('alerts-feed').innerHTML = alerts.length === 0
      ? '<p class="sub">No alerts recorded yet. Run any attack simulation to inspect explainable evidence.</p>'
      : alerts.map(a => `
        <div class="alert-card ${esc(a.severity || 'HIGH')}">
          <div style="display:flex;justify-content:space-between;font-weight:700;font-size:12.5px;">
            <span>[${esc(a.severity || 'HIGH')}] ${esc(a.rule_name)}</span>
            <span class="mono" style="color:var(--muted);">${esc(a.service || '')}</span>
          </div>
          <div style="font-size:12.5px;margin:4px 0;">${esc(a.description || '')}</div>
          <div class="mono" style="font-size:11px;color:var(--muted);">Subject: ${esc(a.subject || '-')} | Evidence: ${esc(JSON.stringify(a.evidence || {}))}</div>
        </div>
      `).join('');

    if (s.eval_metrics) {
      const m = s.eval_metrics;
      document.getElementById('eval-metrics-box').innerHTML = `
        <div class="grid-4">
          <div class="chk-item pass"><span class="mono">F1 Score</span><strong>${esc(m.f1_score)}</strong></div>
          <div class="chk-item pass"><span class="mono">Precision / Recall</span><strong>${esc(m.precision)} / ${esc(m.recall)}</strong></div>
          <div class="chk-item pass"><span class="mono">MTTA</span><strong>${esc(m.mtta_ms)} ms</strong></div>
          <div class="chk-item pass"><span class="mono">FP / 1k Events</span><strong>${esc(m.false_alerts_per_1k)}</strong></div>
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
  btn.textContent = 'Running All Verification Checks...';
  try {
    await apiCall('/api/sandbox/pqc-transfer', {message: 'Auto-Audit Verified Wire #101', profile: 'v1'}, 'msg-out', 'msg-verdict');
    await apiCall('/api/sandbox/pqc-transfer', {message: 'Multi-Family Paranoid Wire #102', profile: 'v2-paranoid'}, 'msg-out', 'msg-verdict');
    await apiCall('/api/sandbox/file-share/validate', {preset: 'valid_png'}, 'msg-out', 'msg-verdict');
    await apiCall('/api/sandbox/attack/replay', {}, 'msg-out', 'msg-verdict');
    await apiCall('/api/sandbox/attack/recipient-swap', {}, 'msg-out', 'msg-verdict');
    await apiCall('/api/sandbox/attack/forward-secrecy', {}, 'msg-out', 'msg-verdict');
    await apiCall('/api/sandbox/attack/session-resumption', {}, 'msg-out', 'msg-verdict');
    await apiCall('/api/sandbox/attack/loss-reorder', {}, 'msg-out', 'msg-verdict');
    await apiCall('/api/sandbox/lifecycle/rotate', {grace_seconds: 1.0}, 'life-out', 'life-verdict');
    await apiCall('/api/sandbox/lifecycle/test-old-key', {}, 'life-out', 'life-verdict');
    await new Promise(r => setTimeout(r, 1150));
    await apiCall('/api/sandbox/lifecycle/test-old-key', {}, 'life-out', 'life-verdict');
    await apiCall('/api/sandbox/lifecycle/revoke-and-reenroll', {mode: 'revoke'}, 'life-out', 'life-verdict');
    await apiCall('/api/sandbox/lifecycle/revoke-and-reenroll', {mode: 'reenroll'}, 'life-out', 'life-verdict');
    await apiCall('/api/sandbox/resilience/crash-recovery', {}, 'life-out', 'life-verdict');
    await apiCall('/api/sandbox/resilience/backup', {tamper: false}, 'life-out', 'life-verdict');
    await apiCall('/api/sandbox/resilience/backup', {tamper: true}, 'life-out', 'life-verdict');
    await apiCall('/api/sandbox/policy/device-timezone', {mode: 'second_device', user_id: 'alice', device_id: 'dev-rogue-2', timezone: 'Asia/Kolkata'}, 'life-out', 'life-verdict');
    await apiCall('/api/sandbox/authority/console-action', {mode: 'suspicious', user_id: 'alice', role: 'admin', action: 'DISABLE_AUDIT'}, 'life-out', 'life-verdict');
    await apiCall('/api/sandbox/audit/injection', {}, 'audit-out', 'audit-verdict');
    await apiCall('/api/sandbox/toolkit/adapter-run', {mode: 'full_suite'}, 'adapter-out', null);
    await apiCall('/api/sandbox/detector/lateral-movement', {}, 'det-out', 'det-verdict');
    await apiCall('/api/sandbox/detector/privilege-escalation', {}, 'det-out', 'det-verdict');
    await apiCall('/api/sandbox/detector/clock-skew', {}, 'det-out', 'det-verdict');
    await apiCall('/api/sandbox/detector/eval-metrics', {}, 'det-out', 'det-verdict');
    await runPracticeAnalysis(true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run All 12 Scenarios';
    await refreshState();
  }
}

refreshState();
loadRepoTests();
setInterval(refreshState, 4000);
</script>
</body>
</html>
"""
