"""Build the two-page project brief from measured, defensible claims.

The brief is generated, not hand-edited. It reads:

- ``DEMO_VIDEO_URL`` from the environment (empty means "video pending").
- ``reports/measurements.json`` (written by ``scripts/benchmark.py``) for the
  performance figures and their provenance.

Usage:
    .venv/bin/python scripts/build_brief.py            # write docs/project_brief.html
    .venv/bin/python scripts/build_brief.py --pdf      # also render the PDF
"""

from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "docs" / "project_brief.html"
PDF_PATH = REPO_ROOT / "docs" / "project_brief.pdf"
MEASUREMENTS_PATH = REPO_ROOT / "reports" / "measurements.json"

CHROME_CANDIDATES = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
)


def _load_measurements() -> dict[str, Any] | None:
    if not MEASUREMENTS_PATH.exists():
        return None
    try:
        return json.loads(MEASUREMENTS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _fmt(value: float) -> str:
    return f"{value:.2f}"


def _video_line() -> str:
    url = os.environ.get("DEMO_VIDEO_URL", "").strip()
    if not url:
        return (
            "Demo video: <strong>pending</strong> (human-supplied; shot list in "
            "<code>docs/DEMO_VIDEO.md</code>)"
        )
    safe = html.escape(url)
    return f'Demo video: <a href="{safe}">{safe}</a>'


def _measurement_table(measurements: dict[str, Any] | None) -> str:
    if not measurements:
        return (
            "<p class=\"note\">No measured results are checked in yet. Run "
            "<code>.venv/bin/python scripts/benchmark.py</code> before publishing "
            "this brief.</p>"
        )
    prov = measurements["provenance"]
    env = measurements["envelope"]
    kem = measurements["kem"]
    sig = measurements["signature"]
    rev = measurements["revocation"]
    det = measurements["detector"]
    ev = measurements["detector_eval"]
    cm = ev["confusion_matrix"]
    return f"""
    <table>
      <tr><th>Path</th><th>p50</th><th>p95</th><th>p99</th><th>Throughput</th></tr>
      <tr><td>Envelope seal (ML-DSA-65 + AES-256-GCM)</td>
          <td>{_fmt(env['seal']['p50_ms'])} ms</td><td>{_fmt(env['seal']['p95_ms'])} ms</td>
          <td>{_fmt(env['seal']['p99_ms'])} ms</td><td>{_fmt(env['seal']['throughput_ops_sec'])} ops/s</td></tr>
      <tr><td>Envelope open (verify + decrypt)</td>
          <td>{_fmt(env['open']['p50_ms'])} ms</td><td>{_fmt(env['open']['p95_ms'])} ms</td>
          <td>{_fmt(env['open']['p99_ms'])} ms</td><td>{_fmt(env['open']['throughput_ops_sec'])} ops/s</td></tr>
      <tr><td>ML-KEM-768 keygen + encaps + decaps</td>
          <td>{_fmt(kem['p50_ms'])} ms</td><td>{_fmt(kem['p95_ms'])} ms</td>
          <td>{_fmt(kem['p99_ms'])} ms</td><td>{_fmt(kem['throughput_ops_sec'])} ops/s</td></tr>
      <tr><td>ML-DSA-65 sign + verify</td>
          <td>{_fmt(sig['p50_ms'])} ms</td><td>{_fmt(sig['p95_ms'])} ms</td>
          <td>{_fmt(sig['p99_ms'])} ms</td><td>{_fmt(sig['throughput_ops_sec'])} ops/s</td></tr>
      <tr><td>Revocation propagation, 3 nodes (M={rev['m_runs']})</td>
          <td>{_fmt(rev['p50_ms'])} ms</td><td>{_fmt(rev['p95_ms'])} ms</td>
          <td>{_fmt(rev['p99_ms'])} ms</td><td>TestClient + SQLite</td></tr>
      <tr><td>Detector rule evaluation</td>
          <td colspan="3">deterministic in-process</td>
          <td>{_fmt(det['throughput_events_sec'])} events/s</td></tr>
    </table>
    <p class="note">Measured {html.escape(prov['date_utc'])} on {html.escape(prov['cpu'])},
    {html.escape(prov['os'])}, Python {html.escape(prov['python'])},
    Node {html.escape(prov['node'])}, commit <code>{html.escape(prov['commit'][:12])}</code>.
    Method: {prov['warmup_iterations']} warm-up iterations, {prov['measured_runs']} runs,
    median. Source: <code>docs/MEASUREMENTS.md</code>.</p>
    <p class="note"><strong>Detector accuracy is synthetic only.</strong>
    The {ev['events']}-event labelled set is hand-built for rule regression
    tests, not a production corpus: TP={cm['tp']}, FP={cm['fp']},
    TN={cm['tn']}, FN={cm['fn']}; precision {ev['precision']:.2f},
    recall {ev['recall']:.2f}, F1 {ev['f1']:.2f},
    FP/1k {ev['false_positives_per_1k']:.2f}. Do not cite as real-world accuracy.</p>
    """


def render_html() -> str:
    measurements = _load_measurements()
    table = _measurement_table(measurements)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Trust-But-Verify: Project Brief</title>
<style>
  @page {{ size: A4; margin: 14mm 15mm; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: "Helvetica Neue", Arial, sans-serif; font-size: 9.1pt;
         line-height: 1.32; color: #111; margin: 0; }}
  h1 {{ font-size: 17pt; margin: 0 0 2mm; color: #0b3d6b; }}
  h2 {{ font-size: 11pt; margin: 4mm 0 1.5mm; color: #0b3d6b;
        border-bottom: 0.4mm solid #0b3d6b; padding-bottom: 0.6mm; }}
  h3 {{ font-size: 9.6pt; margin: 2.5mm 0 1mm; }}
  p {{ margin: 0 0 1.6mm; }}
  ul {{ margin: 0 0 1.8mm 4.5mm; padding: 0; }}
  li {{ margin: 0 0 0.7mm; }}
  .sub {{ font-size: 10pt; color: #333; margin-bottom: 1mm; }}
  .meta {{ font-size: 8.3pt; color: #444; margin-bottom: 2mm; }}
  .note {{ font-size: 7.8pt; color: #444; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 7.9pt; margin: 1mm 0 1.5mm; }}
  th, td {{ border: 0.2mm solid #bbb; padding: 0.9mm 1.2mm; text-align: left; }}
  th {{ background: #e8eef5; }}
  code {{ font-family: "SFMono-Regular", Menlo, monospace; font-size: 8pt; }}
  .page {{ page-break-after: always; }}
  .page:last-child {{ page-break-after: auto; }}
  .two {{ display: flex; gap: 4mm; }}
  .two > div {{ flex: 1; }}
  .box {{ border: 0.3mm solid #0b3d6b; background: #f5f8fb; padding: 1.6mm 2mm; }}
</style>
</head>
<body>

<section class="page">
  <h1>TRUST-BUT-VERIFY: PROJECT BRIEF</h1>
  <div class="sub">Post-quantum zero-trust messaging and explainable audit detection</div>
  <div class="meta">Track: Security, Systems &amp; Post-Quantum Defense &nbsp;|&nbsp;
  Reference implementation for a hackathon submission &nbsp;|&nbsp; {_video_line()}</div>

  <h2>1. What this submission is</h2>
  <p>A Python 3.11 reference implementation of an end-to-end protected messaging
  path with post-quantum key establishment and signatures, authenticated
  envelopes, a durable identity/key lifecycle, a tamper-evident audit log, and a
  deterministic rule-based detector. It is a sandbox/reference system, not a
  production deployment.</p>
  <ul>
    <li><strong>Confidentiality and authenticity:</strong> ML-KEM-768 key
    encapsulation, ML-DSA-65 signatures, AES-256-GCM with an HMAC-SHA256
    key-commitment tag, and HKDF-SHA256 derivation.</li>
    <li><strong>Recipient/device binding and replay defence:</strong> all routing
    metadata is in the AEAD AAD; duplicate message IDs are rejected by a
    persistent replay cache.</li>
    <li><strong>Identity lifecycle:</strong> signed rotation cutoffs with a grace
    period, authenticated revocation with cross-node propagation, and
    owner-or-admin-authorized enrollment/recovery.</li>
    <li><strong>Audit and detection:</strong> SHA-256 hash-chained JSONL audit
    log, ML-DSA-signed checkpoints, out-of-band anchors, and a deterministic
    detector with per-alert identity/service/event context.</li>
  </ul>

  <h2>2. Architecture</h2>
  <div class="two">
    <div>
      <h3>Crypto layer</h3>
      <p><code>src/crypto</code>: envelope seal/open, AEAD, replay cache,
      handshake, chunked delivery, resumption. Primitives come from
      <code>pqcrypto</code> (liboqs-backed ML-KEM/ML-DSA) and
      <code>cryptography</code>; no custom cryptography is implemented.</p>
      <h3>Identity and key authority</h3>
      <p><code>src/identity_keys</code>: FastAPI service, SQLAlchemy/Alembic
      schema, enrollment, rotation cutoffs, revocation, re-enrollment, backup,
      and rate limits.</p>
    </div>
    <div>
      <h3>Audit and detector</h3>
      <p><code>src/audit</code> and <code>src/detector</code>: chained audit
      logging with signed checkpoints and an operator verifier; deterministic
      rule and graph checks with clock-skew buffering.</p>
      <h3>Sandbox and CLI</h3>
      <p><code>demo/node</code> and <code>src/cli.py</code>: multi-node HTTP
      sandbox, operator CLI, reproducible demos, and the judge walkthrough.</p>
    </div>
  </div>

  <h2>3. Evaluation highlights (measured, not estimated)</h2>
  {table}

  <h2>4. Scope and non-goals</h2>
  <ul>
    <li>No formal verification and no claim of production readiness.</li>
    <li>No AI/ML detector; the detector is deterministic and rule-based.</li>
    <li>Keys are generated in process and the sandbox uses an environment-supplied
    wrap key and HMAC cluster secret instead of an external KMS/HSM.</li>
    <li>The audit chain detects edits when compared with a trusted head or signed
    checkpoint; an attacker who can replace the entire log and its checkpoint
    key can forge a new chain.</li>
  </ul>
</section>

<section class="page">
  <h1>THREAT MODEL &amp; SECURITY SPECIFICATION</h1>
  <div class="sub">STRIDE-oriented adversary and control matrix</div>

  <h2>1. Adversaries considered</h2>
  <ul>
    <li><strong>Network attacker:</strong> observes, drops, reorders, replays, or
    tampers with messages. Mitigation: AEAD, ML-DSA signatures, recipient
    binding, replay cache, chunk authentication.</li>
    <li><strong>Future quantum adversary (harvest-now-decrypt-later):</strong>
    Mitigation: ML-KEM-768 and ML-DSA-65; ephemeral session keys provide forward
    secrecy for completed sessions.</li>
    <li><strong>Compromised node or malicious insider:</strong> attempts
    unauthorized privilege use, lateral movement, or audit tampering. Mitigation:
    service-DAG policy checks, role barriers, hash-chained audit entries, signed
    checkpoints, and out-of-band anchors.</li>
    <li><strong>Stolen device or key:</strong> Mitigation: signed revocation,
    cross-node propagation, stale-state fail-closed authorization, and
    owner-or-admin re-enrollment.</li>
    <li><strong>Operator error / crash:</strong> Mitigation: fsynced write-ahead
    log, authenticated backups, atomic rotation cutoffs.</li>
  </ul>

  <h2>2. STRIDE controls</h2>
  <table>
    <tr><th>Threat</th><th>Control in this submission</th></tr>
    <tr><td>Spoofing</td><td>ML-DSA-65 signatures over canonical envelope and
    checkpoint bytes; pinned verification keys; enrollment authorization.</td></tr>
    <tr><td>Tampering</td><td>AES-256-GCM authentication, key-commitment tag,
    SHA-256 audit chain, signed checkpoints, anchor comparison.</td></tr>
    <tr><td>Repudiation</td><td>Signed checkpoints, monotonic sequence numbers,
    and actor-attributed audit events.</td></tr>
    <tr><td>Information disclosure</td><td>ML-KEM-768 + AES-256-GCM; ISO/IEC
    7816-4 bucket padding available for length hiding.</td></tr>
    <tr><td>Denial of service</td><td>Persistent replay cache, bounded rate
    limits, burst thresholds, stale-state fail-closed behaviour.</td></tr>
    <tr><td>Elevation of privilege</td><td>Role/permission checks, service-DAG
    lateral-movement rules, owner/admin authorization on sensitive routes.</td></tr>
  </table>

  <h2>3. Reliability and recovery</h2>
  <ul>
    <li><strong>Mid-operation crash:</strong> the write-ahead log discards torn
    writes and replays only complete, checksummed entries.</li>
    <li><strong>Damaged backup:</strong> HMAC-SHA3-512 authentication rejects
    tampered or truncated snapshots.</li>
    <li><strong>Clock skew:</strong> the arrival buffer tolerates ±2000 ms and
    flags larger skew instead of silently dropping evidence.</li>
  </ul>

  <h2>4. Reproduce the claims</h2>
  <ol>
    <li><code>make setup</code> — create <code>.venv</code> with Python 3.11 and
    install pinned dependencies.</li>
    <li><code>make test</code> — run the full root suite.</li>
    <li><code>make gates</code> — lint, type check, audit-log CLI self-check, and
    tests.</li>
    <li><code>make bench</code> — regenerate
    <code>reports/measurements.json</code> and <code>docs/MEASUREMENTS.md</code>;
    the brief table is built from the same file.</li>
    <li><code>make demo</code> — run the deterministic judge walkthrough.</li>
  </ol>

  <div class="box">
    <p><strong>Human-only artifacts:</strong> the 5-minute demo recording and its
    upload are not generated here. The shot list and checklist are in
    <code>docs/DEMO_VIDEO.md</code>; set <code>DEMO_VIDEO_URL</code> and rebuild
    this brief once the recording exists.</p>
    <p class="note">Brief generated by <code>scripts/build_brief.py</code>. The
    measured table is read from <code>reports/measurements.json</code>; the
    detector row is explicitly labelled synthetic. No unmeasured performance or
    accuracy claim is made.</p>
  </div>
</section>

</body>
</html>
"""


def _find_chrome() -> str | None:
    env = os.environ.get("CHROME_BIN")
    if env and Path(env).exists():
        return env
    for candidate in CHROME_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return shutil.which("google-chrome") or shutil.which("chromium")


def render_pdf(chrome: str) -> None:
    HTML_PATH.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as profile:
        cmd = [
            chrome,
            "--headless",
            "--disable-gpu",
            "--no-pdf-header-footer",
            f"--user-data-dir={profile}",
            f"--print-to-pdf={PDF_PATH}",
            HTML_PATH.as_uri(),
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the two-page project brief.")
    parser.add_argument("--pdf", action="store_true", help="also render the PDF with headless Chrome")
    args = parser.parse_args()

    HTML_PATH.parent.mkdir(parents=True, exist_ok=True)
    HTML_PATH.write_text(render_html(), encoding="utf-8")
    print(f"Wrote {HTML_PATH}")

    if args.pdf:
        chrome = _find_chrome()
        if not chrome:
            print("No Chrome/Chromium found; HTML written but PDF not rendered.", file=sys.stderr)
            return 1
        render_pdf(chrome)
        print(f"Wrote {PDF_PATH} with {chrome}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
