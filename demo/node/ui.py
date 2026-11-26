"""Self-contained Security Operations & Track 4 Workbench UI (Light Blue/White SaaS Layout)."""

from __future__ import annotations


def render_dashboard_html() -> str:
    """Return the Track 4 Trust, But Verify workbench HTML with login landing and sidebar navigation."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Trust, But Verify — Post-Quantum Zero-Trust Security Console</title>
<style>
  :root {
    --bg-page: #f4f7fb;
    --bg-card: #ffffff;
    --bg-sidebar: #ffffff;
    --bg-subtle: #f8fafc;
    --text-primary: #0f172a;
    --text-secondary: #334155;
    --text-muted: #64748b;
    --border: #e2e8f0;
    --blue: #2563eb;
    --blue-hover: #1d4ed8;
    --blue-soft: #eff6ff;
    --blue-border: #bfdbfe;
    --blue-text: #1e40af;
    --green-soft: #dcfce7;
    --green-text: #166534;
    --amber-soft: #fef3c7;
    --amber-text: #92400e;
    --red-soft: #fee2e2;
    --red-text: #991b1b;
    --shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.04);
    --shadow-md: 0 8px 24px rgba(15, 23, 42, 0.08);
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }

  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg-page);
    color: var(--text-primary);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }

  a { color: var(--blue); text-decoration: none; }
  a:hover { text-decoration: underline; }
  :focus-visible { outline: 2px solid var(--blue); outline-offset: 2px; }

  /* ── Login Landing Screen ── */
  .login-screen {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: radial-gradient(circle at top left, #dbeafe 0%, #f4f7fb 45%, #f8fafc 100%);
  }
  .login-card {
    width: 100%;
    max-width: 470px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 28px;
    box-shadow: var(--shadow-md);
  }
  .brand-row { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
  .shield-box {
    width: 38px; height: 38px; border-radius: 10px;
    background: var(--blue); color: #fff;
    display: grid; place-items: center; flex-shrink: 0;
    box-shadow: 0 4px 12px rgba(37, 99, 235, 0.28);
  }
  .login-card h1 { margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); }
  .login-sub { font-size: 12.5px; color: var(--text-muted); margin: 0; }
  .info-banner {
    background: var(--blue-soft);
    border: 1px solid var(--blue-border);
    color: var(--blue-text);
    border-radius: 10px;
    padding: 10px 12px;
    font-size: 12.5px;
    margin-bottom: 16px;
  }
  .quick-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    margin-top: 10px;
  }
  .quick-acct {
    text-align: left;
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 9px 11px;
    cursor: pointer;
    transition: border-color .15s, background .15s;
  }
  .quick-acct:hover { border-color: var(--blue); background: var(--blue-soft); }
  .quick-acct strong { display: block; font-size: 12.5px; color: var(--text-primary); }
  .quick-acct span { font-size: 11px; color: var(--text-muted); }

  /* ── App Shell (Sidebar + Main) ── */
  .app-shell { display: none; min-height: 100vh; }
  .app-shell.visible { display: flex; }

  .sidebar {
    width: 252px;
    height: 100vh;
    position: sticky;
    top: 0;
    background: var(--bg-sidebar);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding: 18px 14px 14px;
    flex-shrink: 0;
    z-index: 40;
  }
  .sidebar-brand {
    display: flex; align-items: center; gap: 10px;
    padding: 2px 6px 16px; border-bottom: 1px solid var(--border);
  }
  .sidebar-wordmark {
    font-size: 14px; font-weight: 800; letter-spacing: 0.04em;
    color: var(--blue); text-transform: uppercase;
  }
  .sidebar-tagline { font-size: 11px; color: var(--text-muted); }

  .sidebar-nav { flex: 1; overflow-y: auto; padding-top: 8px; }
  .nav-group {
    font-size: 10.5px; font-weight: 700; color: #94a3b8;
    text-transform: uppercase; letter-spacing: 0.08em;
    padding: 12px 10px 4px;
  }
  .nav-btn {
    width: 100%;
    display: flex; align-items: center; gap: 10px;
    padding: 8.5px 11px; margin-bottom: 2px;
    border: none; border-radius: 8px; background: transparent;
    color: var(--text-secondary); font-size: 13.5px; font-weight: 500;
    cursor: pointer; text-align: left; font-family: inherit;
    transition: background .12s, color .12s;
  }
  .nav-btn:hover { background: #f1f5f9; color: var(--text-primary); }
  .nav-btn.active { background: var(--blue); color: #ffffff; font-weight: 600; }
  .nav-btn svg { width: 16px; height: 16px; flex-shrink: 0; }
  .nav-btn.hidden-role { display: none; }

  .sidebar-footer {
    border-top: 1px solid var(--border);
    padding-top: 12px;
    margin-top: 10px;
    display: flex; flex-direction: column; gap: 10px;
  }
  .user-row { display: flex; align-items: center; gap: 10px; }
  .avatar {
    width: 34px; height: 34px; border-radius: 50%;
    background: var(--blue); color: #fff;
    font-size: 12px; font-weight: 700; display: grid; place-items: center; flex-shrink: 0;
  }
  .user-meta { flex: 1; min-width: 0; }
  .user-name { font-size: 13px; font-weight: 600; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .user-email { font-size: 11px; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  /* ── Main Column & Sticky White Navbar ── */
  .main-col { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .topbar {
    height: 64px;
    background: #ffffff;
    border-bottom: 1px solid var(--border);
    padding: 0 24px;
    display: flex; align-items: center; justify-content: space-between; gap: 14px;
    position: sticky; top: 0; z-index: 30;
  }
  .topbar-left { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .topbar-title { margin: 0; font-size: 17px; font-weight: 700; color: var(--text-primary); white-space: nowrap; }
  .menu-toggle {
    display: none; border: 1px solid var(--border); background: #fff;
    border-radius: 8px; padding: 6px 9px; cursor: pointer; color: var(--text-secondary);
  }

  .topbar-right { display: flex; align-items: center; gap: 10px; }
  .search-wrap { position: relative; }
  .search-box {
    display: flex; align-items: center; gap: 8px;
    background: var(--bg-subtle); border: 1px solid var(--border);
    border-radius: 9px; padding: 6px 12px; width: 270px;
  }
  .search-box:focus-within { background: #fff; border-color: var(--blue); box-shadow: 0 0 0 3px rgba(37,99,235,0.12); }
  .search-box input {
    border: none; background: transparent; padding: 2px 0; font-size: 13px;
    width: 100%; outline: none; color: var(--text-primary);
  }
  .search-dropdown {
    position: absolute; top: calc(100% + 6px); left: 0; right: 0;
    background: #fff; border: 1px solid var(--border); border-radius: 10px;
    box-shadow: var(--shadow-md); max-height: 280px; overflow: auto;
    display: none; z-index: 50;
  }
  .search-dropdown.open { display: block; }
  .search-hit {
    padding: 9px 12px; border-bottom: 1px solid #f1f5f9; cursor: pointer; display: block; width: 100%;
    text-align: left; border-left: none; border-right: none; border-top: none; background: #fff; font-family: inherit;
  }
  .search-hit:hover { background: var(--blue-soft); }
  .search-hit strong { display: block; font-size: 12.5px; color: var(--text-primary); }
  .search-hit span { font-size: 11.5px; color: var(--text-muted); }

  /* ── Page Container & Clean Cards ── */
  .page-body { padding: 22px 26px 48px; max-width: 1380px; width: 100%; margin: 0 auto; }
  .view-panel { display: none; }
  .view-panel.active { display: block; }

  .page-head {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
    gap: 12px; margin-bottom: 18px;
  }
  .page-head h2 { margin: 0; font-size: 18px; font-weight: 700; }
  .page-head p { margin: 2px 0 0; font-size: 13px; color: var(--text-muted); }

  .grid-4 { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 16px; }
  .grid-3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; margin-bottom: 16px; }
  .grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; margin-bottom: 16px; }
  .row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .row-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; }
  @media (max-width: 1020px) { .grid-4, .grid-3, .grid-2 { grid-template-columns: 1fr; } }
  @media (max-width: 960px) {
    .sidebar { position: fixed; left: -270px; transition: left .2s ease; }
    .sidebar.mobile-open { left: 0; box-shadow: var(--shadow-md); }
    .menu-toggle { display: inline-flex; }
    .search-box { width: 190px; }
  }
  @media (max-width: 680px) { .row-2, .row-3 { grid-template-columns: 1fr; } .search-wrap { display: none; } }

  .card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 20px;
    box-shadow: var(--shadow-sm);
  }
  .card h3 { margin: 0 0 6px; font-size: 15px; font-weight: 700; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .sub { margin: 0 0 14px; font-size: 12.5px; color: var(--text-muted); }

  .stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 18px;
    box-shadow: var(--shadow-sm);
  }
  .stat-label { font-size: 12px; font-weight: 600; color: var(--text-muted); }
  .stat-value { font-size: 24px; font-weight: 800; color: var(--text-primary); margin: 4px 0 2px; line-height: 1.2; }
  .stat-meta { font-size: 11.5px; color: var(--blue-text); font-weight: 500; }

  /* ── Badges, Buttons & Form Controls ── */
  .badge {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 3px 9px; border-radius: 999px; font-size: 11.5px; font-weight: 600;
    background: #f1f5f9; color: var(--text-secondary); white-space: nowrap;
  }
  .badge.blue { background: var(--blue-soft); color: var(--blue-text); }
  .badge.ok { background: var(--green-soft); color: var(--green-text); }
  .badge.warn { background: var(--amber-soft); color: var(--amber-text); }
  .badge.bad { background: var(--red-soft); color: var(--red-text); }

  .btn-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  button.btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 6px;
    padding: 8px 14px; border-radius: 8px; font-size: 13px; font-weight: 600;
    border: 1px solid var(--border); background: #ffffff; color: var(--text-secondary);
    cursor: pointer; font-family: inherit; transition: background .12s, border-color .12s, transform .05s;
  }
  button.btn:hover { background: #f8fafc; border-color: #cbd5e1; color: var(--text-primary); }
  button.btn:active { transform: translateY(1px); }
  button.btn:disabled { opacity: 0.6; cursor: wait; }
  button.btn-primary { background: var(--blue); border-color: var(--blue); color: #ffffff; }
  button.btn-primary:hover { background: var(--blue-hover); border-color: var(--blue-hover); color: #ffffff; }
  button.btn-soft { background: var(--blue-soft); border-color: var(--blue-border); color: var(--blue-text); }
  button.btn-soft:hover { background: #dbeafe; }
  button.btn-danger { background: #fef2f2; border-color: #fecaca; color: var(--red-text); }
  button.btn-danger:hover { background: #fee2e2; }
  button.btn-warn { background: #fffbeb; border-color: #fde68a; color: var(--amber-text); }

  .field { margin-bottom: 12px; }
  .field label { display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 5px; }
  input, select, textarea {
    width: 100%; background: #ffffff; border: 1px solid #cbd5e1;
    border-radius: 8px; padding: 8px 11px; font-size: 13px;
    color: var(--text-primary); font-family: inherit;
  }
  input[type="checkbox"] { width: auto; }
  input:focus, select:focus, textarea:focus { border-color: var(--blue); outline: none; box-shadow: 0 0 0 3px rgba(37,99,235,0.12); }
  textarea { font-family: var(--mono); font-size: 12px; min-height: 88px; resize: vertical; }

  .mono { font-family: var(--mono); font-size: 12px; }
  .kv { display: flex; justify-content: space-between; align-items: center; gap: 10px; padding: 7px 0; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
  .kv:last-child { border-bottom: none; }
  .kv span:first-child { color: var(--text-muted); }

  .verdict-box {
    border-radius: 9px; padding: 11px 14px; margin-bottom: 10px;
    border: 1px solid var(--border); background: var(--bg-subtle);
  }
  .verdict-box.ok { border-color: #bbf7d0; background: #f0fdf4; color: var(--green-text); }
  .verdict-box.blocked { border-color: #fde68a; background: #fffbeb; color: var(--amber-text); }
  .verdict-box.bad { border-color: #fecaca; background: #fef2f2; color: var(--red-text); }
  .verdict-title { font-weight: 700; font-size: 13px; }
  .verdict-sub { font-size: 12px; opacity: 0.92; margin-top: 2px; }

  .dropzone {
    border: 2px dashed var(--blue-border); border-radius: 12px; padding: 22px;
    background: var(--blue-soft); text-align: center; cursor: pointer;
    transition: background .15s, border-color .15s;
  }
  .dropzone.drag { background: #dbeafe; border-color: var(--blue); }
  .file-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
  .file-chip {
    background: #fff; border: 1px solid var(--blue-border); border-radius: 999px;
    padding: 3px 10px; font-family: var(--mono); font-size: 11px; color: var(--blue-text);
  }

  .test-list {
    max-height: 220px; overflow: auto; border: 1px solid var(--border);
    border-radius: 9px; background: var(--bg-subtle); padding: 8px;
  }
  .test-item {
    display: flex; align-items: center; justify-content: space-between;
    padding: 5px 6px; border-bottom: 1px solid #f1f5f9; font-family: var(--mono); font-size: 12px;
  }
  .test-item label { display: flex; align-items: center; gap: 8px; cursor: pointer; }

  .checklist-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
  @media (max-width: 980px) { .checklist-grid { grid-template-columns: 1fr; } }
  .chk-item {
    background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 9px; padding: 11px 13px;
  }
  .chk-item.pass { border-color: #bbf7d0; background: #f0fdf4; }
  .chk-item.fail { border-color: #fecaca; background: #fef2f2; }
  .chk-top { display: flex; justify-content: space-between; align-items: center; font-weight: 600; font-size: 12.5px; gap: 6px; }
  .chk-sum { font-size: 11.5px; color: var(--text-muted); margin-top: 4px; }

  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  th { color: var(--text-muted); font-weight: 600; background: var(--bg-subtle); font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.03em; }

  details.raw-json { margin-top: 10px; }
  details.raw-json summary { cursor: pointer; font-size: 12px; font-weight: 600; color: var(--blue); }
  pre.console {
    background: #f8fafc; border: 1px solid var(--border); border-radius: 8px;
    padding: 12px; font-family: var(--mono); font-size: 11.5px; color: #1e293b;
    max-height: 260px; overflow: auto; white-space: pre-wrap; word-break: break-word; margin: 8px 0 0;
  }

  .alert-card {
    border: 1px solid #fecaca; background: #fef2f2;
    border-radius: 9px; padding: 11px 13px; margin-bottom: 8px;
  }
  .alert-card.HIGH { border-color: #fde68a; background: #fffbeb; }
  .progress-track { height: 8px; background: #e2e8f0; border-radius: 999px; overflow: hidden; margin-top: 8px; }
  .progress-fill { height: 100%; background: var(--blue); width: 0%; transition: width .3s ease; }

  .dag-box { background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 10px; padding: 12px; margin-top: 12px; }
  .cmd-line {
    background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px;
    display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 8px;
  }
  .cmd-line code { font-family: var(--mono); font-size: 11.5px; color: var(--blue-text); word-break: break-all; }
</style>
</head>
<body>

<!-- ── LOGIN LANDING SCREEN ── -->
<section id="login-screen" class="login-screen" aria-label="Sign In">
  <div class="login-card">
    <div class="brand-row">
      <div class="shield-box" aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 2L4 5.5V11.5C4 16.8 7.4 21.5 12 23C16.6 21.5 20 16.8 20 11.5V5.5L12 2Z" />
          <path d="M9 12.2L11 14.2L15.5 9.7" />
        </svg>
      </div>
      <div>
        <h1>Trust, But Verify Sign In</h1>
        <p class="login-sub">Post-Quantum Identity, Access Control &amp; Audit Console</p>
      </div>
    </div>

    <div class="info-banner">
      Choose an operator or resource-owner identity to enter the security console. Admin sessions unlock key rotation, cluster revocation, backup tamper recovery, and audit actions.
    </div>

    <form onsubmit="submitLoginForm(event)">
      <div class="field">
        <label for="login-username">Identity Username</label>
        <input id="login-username" value="admin" required autocomplete="username" />
      </div>
      <div class="field">
        <label for="login-role">Session Role Scope</label>
        <select id="login-role">
          <option value="ADMIN" selected>Security Admin (Full Cluster &amp; Recovery Controls)</option>
          <option value="USER">Resource Owner (Messaging, Devices &amp; Audit Viewer)</option>
        </select>
      </div>
      <button type="submit" id="btn-signin" class="btn btn-primary" style="width:100%;padding:10px 14px;">Sign In to Console</button>
    </form>

    <div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--border);">
      <div class="stat-label">Quick Sign-In Synthetic Identities</div>
      <div class="quick-grid">
        <button type="button" class="quick-acct" onclick="quickSignIn('admin', 'ADMIN')">
          <strong>Security Admin</strong>
          <span>ADMIN &middot; Full Controls</span>
        </button>
        <button type="button" class="quick-acct" onclick="quickSignIn('alice', 'USER')">
          <strong>Alice (Owner)</strong>
          <span>USER &middot; Device &amp; Messaging</span>
        </button>
        <button type="button" class="quick-acct" onclick="quickSignIn('bob', 'USER')">
          <strong>Bob (Peer)</strong>
          <span>USER &middot; Recipient Node-B</span>
        </button>
        <button type="button" class="quick-acct" onclick="quickSignIn('charlie', 'ADMIN')">
          <strong>Auditor / Operator</strong>
          <span>ADMIN &middot; Audit &amp; Tests</span>
        </button>
      </div>
    </div>
  </div>
</section>

<!-- ── MAIN DASHBOARD APP SHELL ── -->
<div id="app-shell" class="app-shell">
  <aside id="sidebar" class="sidebar" aria-label="Primary Navigation">
    <div class="sidebar-brand">
      <div class="shield-box" style="width:32px;height:32px;border-radius:8px;" aria-hidden="true">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
          <path d="M12 2L4 5.5V11.5C4 16.8 7.4 21.5 12 23C16.6 21.5 20 16.8 20 11.5V5.5L12 2Z" />
          <path d="M9 12.2L11 14.2L15.5 9.7" />
        </svg>
      </div>
      <div>
        <div class="sidebar-wordmark">TRUST, BUT VERIFY</div>
        <div class="sidebar-tagline">Track 4 Zero-Trust PQC</div>
      </div>
    </div>

    <nav class="sidebar-nav">
      <div class="nav-group">Main Menu</div>
      <button class="nav-btn active" data-view="dashboard" onclick="goView('dashboard')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 10.5L12 3l9 7.5V20a1 1 0 01-1 1h-5v-6H9v6H4a1 1 0 01-1-1z"/></svg>
        <span>Dashboard</span>
      </button>
      <button class="nav-btn" data-view="tests" onclick="goView('tests')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>
        <span>Test Files &amp; Suites</span>
      </button>
      <button class="nav-btn" data-view="messaging" onclick="goView('messaging')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>
        <span>Secure Messaging</span>
      </button>
      <button class="nav-btn" data-view="threats" onclick="goView('threats')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M10.3 3.9L2.8 17a2 2 0 001.7 3h15a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>
        <span>Threat Detection</span>
      </button>

      <div class="nav-group">Security</div>
      <button class="nav-btn" data-view="devices" onclick="goView('devices')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8m-4-4v4"/></svg>
        <span>Devices &amp; Authority</span>
      </button>
      <button class="nav-btn" data-admin="true" data-view="keys" onclick="goView('keys')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M21 2l-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/></svg>
        <span>Key Management</span>
      </button>
      <button class="nav-btn" data-view="audit" onclick="goView('audit')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h6"/></svg>
        <span>Audit Logs</span>
      </button>
      <button class="nav-btn" data-admin="true" data-view="recovery" onclick="goView('recovery')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 103-6.7L3 8m0-5v5h5"/></svg>
        <span>Backup &amp; Recovery</span>
      </button>

      <div class="nav-group">Platform</div>
      <button class="nav-btn" data-view="adapter" onclick="goView('adapter')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 17l6-6-6-6M12 19h8"/></svg>
        <span>Track-4 Adapter</span>
      </button>
      <button class="nav-btn" data-view="guide" onclick="goView('guide')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span>Threat Model &amp; Guide</span>
      </button>
    </nav>

    <div class="sidebar-footer">
      <div class="user-row">
        <div id="sb-avatar" class="avatar">AD</div>
        <div class="user-meta">
          <div id="sb-name" class="user-name">Security Admin</div>
          <div id="sb-email" class="user-email">admin@tbv.local</div>
        </div>
        <button type="button" class="btn" style="padding:6px 8px;" title="Sign out" aria-label="Sign out" onclick="signOut()">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4m7 14l5-5-5-5m5 5H9"/></svg>
        </button>
      </div>
      <button type="button" class="btn" style="width:100%;" onclick="openAccountSwitcher()">Switch Account</button>
    </div>
  </aside>

  <div class="main-col">
    <header class="topbar">
      <div class="topbar-left">
        <button type="button" class="menu-toggle" aria-label="Toggle Menu" onclick="document.getElementById('sidebar').classList.toggle('mobile-open')">&#9776;</button>
        <h2 id="topbar-title" class="topbar-title">Dashboard</h2>
        <span id="hdr-role-badge" class="badge blue">ADMIN</span>
        <span id="hdr-pqc" class="badge">ML-KEM-768 + ML-DSA-65</span>
      </div>

      <div class="topbar-right">
        <div class="search-wrap" id="search-wrap">
          <div class="search-box">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
            <input id="global-search" placeholder="Search views, keys, logs, or tests..." autocomplete="off" oninput="onGlobalSearch()" onfocus="onGlobalSearch()" />
          </div>
          <div id="search-dropdown" class="search-dropdown"></div>
        </div>
        <button type="button" class="btn btn-primary" id="btn-run-all" onclick="runAll12()">Run All 12 Scenarios</button>
        <button type="button" class="btn" onclick="refreshState()" title="Refresh cluster telemetry" aria-label="Refresh telemetry">Refresh</button>
        <a class="btn" href="/docs" target="_blank">API Docs</a>
      </div>
    </header>

    <main class="page-body">

      <!-- VIEW 1: DASHBOARD -->
      <section id="view-dashboard" class="view-panel active">
        <div class="page-head">
          <div>
            <h2>Security Overview</h2>
            <p>Real-time cluster posture across post-quantum transport, device locks, hash-chained audit logs, and deterministic detection.</p>
          </div>
          <button class="btn btn-soft" onclick="goView('tests')">Drop Test Files to Verify &rarr;</button>
        </div>

        <div class="grid-4">
          <div class="stat-card">
            <div class="stat-label">Cluster Nodes Online</div>
            <div class="stat-value" id="kpi-nodes">3 / 3</div>
            <div class="stat-meta" id="kpi-uptime">uptime: --</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Track 4 Objectives Verified</div>
            <div class="stat-value" id="kpi-score">0 / 12</div>
            <div class="stat-meta">Automated scenario suite</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Audit Hash Chain</div>
            <div class="stat-value" id="kpi-chain">VALID</div>
            <div class="stat-meta" id="kpi-records">0 records</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Security Guardrails</div>
            <div class="stat-value" id="kpi-policy">20 MiB / 1 Dev</div>
            <div class="stat-meta">Zero AI/ML deterministic rules</div>
          </div>
        </div>

        <div class="grid-3" id="nodes-grid"></div>

        <div class="card">
          <h3>
            <span>Track 4 Verification Checklist</span>
            <span class="mono" id="chk-count-lbl">0 / 12 Verified</span>
          </h3>
          <div class="progress-track"><div id="chk-bar" class="progress-fill"></div></div>
          <div id="checklist-grid" class="checklist-grid" style="margin-top:14px;"></div>
        </div>
      </section>

      <!-- VIEW 2: TEST FILES & SUITES -->
      <section id="view-tests" class="view-panel">
        <div class="page-head">
          <div>
            <h2>Test Files &amp; Automated Suites</h2>
            <p>Drop your own <code>events.csv</code> + <code>approvals.json</code> + <code>labels.csv</code>, exported <code>*.log</code> hash chains, <code>track4_service.py</code>, or run repo <code>pytest</code> suites.</p>
          </div>
        </div>

        <div class="grid-2">
          <div class="card">
            <h3>Upload or Drop Test Files</h3>
            <p class="sub">Supports multi-file upload: CSV logs, approval JSONs, audit chains, JSON schemas, media/documents (&le; 20 MiB), and repo <code>.py</code> test files.</p>
            <div id="bundle-dropzone" class="dropzone" onclick="document.getElementById('bundle-picker').click()">
              <strong style="color:var(--blue-text);font-size:14px;">Click to Choose Test Files or Drag &amp; Drop Here</strong>
              <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Multiple files supported (e.g. events.csv + approvals.json + labels.csv)</div>
              <input id="bundle-picker" type="file" multiple style="display:none;" onchange="handleBundleFiles(this.files)" />
            </div>
            <div id="bundle-chips" class="file-chips"></div>
            <div class="btn-row">
              <button class="btn btn-primary" onclick="checkSelectedBundle()">Check Uploaded Files</button>
              <button class="btn" onclick="clearBundleFiles()">Clear</button>
            </div>
          </div>

          <div class="card">
            <h3>Repository Pytest &amp; Track-4-Toolkit Runner</h3>
            <p class="sub">Run official repository verification suites directly from the console.</p>
            <div class="btn-row" style="margin-top:0;margin-bottom:10px;">
              <button class="btn btn-primary" onclick="runSelectedTests(false)">Run Selected Suites</button>
              <button class="btn btn-soft" onclick="runSelectedTests(true)">Run Track-4-Toolkit Validator</button>
              <button class="btn" onclick="runAllPytestSuites()">Run Full Suite</button>
            </div>
            <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;">
              <button class="btn" style="padding:4px 9px;font-size:12px;" onclick="toggleAllTests(true)">Select All</button>
              <button class="btn" style="padding:4px 9px;font-size:12px;" onclick="toggleAllTests(false)">None</button>
              <span id="repo-tests-meta" class="mono" style="color:var(--text-muted);">Loading suites...</span>
            </div>
            <div id="repo-tests-list" class="test-list">Loading...</div>
          </div>
        </div>

        <div class="card">
          <h3>
            <span>Verification Results</span>
            <span id="bundle-status-badge" class="badge blue">Ready</span>
          </h3>
          <div id="bundle-verdict" class="verdict-box">
            <div class="verdict-title">No files checked yet</div>
            <div class="verdict-sub">Upload files on the left or run a suite on the right to see results.</div>
          </div>
          <div id="bundle-results-wrap" style="overflow-x:auto;margin-bottom:10px;"></div>
          <div id="bundle-triage-wrap" style="overflow-x:auto;margin-bottom:10px;"></div>
          <details class="raw-json">
            <summary>View Technical Output &amp; Raw Logs</summary>
            <pre class="console" id="bundle-raw-out">Detailed pytest / validator output will appear here.</pre>
          </details>
        </div>
      </section>

      <!-- VIEW 3: SECURE MESSAGING & FILE GUARD -->
      <section id="view-messaging" class="view-panel">
        <div class="page-head">
          <div>
            <h2>Secure Messaging &amp; File Sharing</h2>
            <p>Post-quantum encrypted transport with recipient binding, forward secrecy, and 20 MiB media magic-byte enforcement.</p>
          </div>
          <div class="btn-row" style="margin-top:0;">
            <button class="btn btn-primary" onclick="runMessagingSuite()">Run Delivery &amp; Attack Checks</button>
          </div>
        </div>

        <div class="grid-4">
          <div class="stat-card">
            <div class="stat-label">Encrypted Envelopes</div>
            <div class="stat-value" id="msg-kpi-count">0</div>
            <div class="stat-meta">Signed &amp; AEAD sealed</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Ephemeral Keys Wiped</div>
            <div class="stat-value" id="msg-kpi-wiped">0</div>
            <div class="stat-meta">Forward secrecy active</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Active Crypto Suites</div>
            <div class="stat-value">v1 / v2</div>
            <div class="stat-meta">ML-KEM-768 &amp; HQC-256 agility</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Shared File Policy</div>
            <div class="stat-value">20 MiB</div>
            <div class="stat-meta">Media + magic-byte guard</div>
          </div>
        </div>

        <div class="grid-2">
          <div class="card">
            <h3>Send Encrypted Envelope</h3>
            <p class="sub">Establishes an ephemeral KEM shared secret with recipient AAD binding and post-quantum signature.</p>
            <div class="row-3">
              <div class="field"><label for="msg-sender">Sender</label><input id="msg-sender" value="alice" /></div>
              <div class="field">
                <label for="msg-recipient">Recipient</label>
                <select id="msg-recipient">
                  <option value="bob" selected>bob (node-b)</option>
                  <option value="charlie">charlie (node-c)</option>
                </select>
              </div>
              <div class="field">
                <label for="msg-profile">PQC Profile</label>
                <select id="msg-profile">
                  <option value="v1" selected>track4/v1 (ML-KEM-768)</option>
                  <option value="v2-paranoid">track4/v2-paranoid (HQC + SLH-DSA)</option>
                </select>
              </div>
            </div>
            <div class="field"><label for="msg-input">Message Plaintext</label><input id="msg-input" value="Approve transfer #8841: $25,000 Escrow-B" /></div>
            <div class="btn-row">
              <button class="btn btn-primary" onclick="sendTransfer()">Send Protected Message</button>
              <button class="btn btn-warn" onclick="apiCall('/api/sandbox/attack/replay', {}, 'msg-out', 'msg-verdict')">Test Replay</button>
              <button class="btn btn-warn" onclick="apiCall('/api/sandbox/attack/recipient-swap', {}, 'msg-out', 'msg-verdict')">Test Recipient Swap</button>
            </div>
            <div class="btn-row">
              <button class="btn btn-soft" onclick="apiCall('/api/sandbox/attack/forward-secrecy', {}, 'msg-out', 'msg-verdict')">Verify Forward Secrecy</button>
              <button class="btn btn-soft" onclick="apiCall('/api/sandbox/attack/session-resumption', {}, 'msg-out', 'msg-verdict')">Test Session Hijack</button>
              <button class="btn btn-soft" onclick="apiCall('/api/sandbox/attack/loss-reorder', {}, 'msg-out', 'msg-verdict')">Test Loss &amp; Reordering</button>
            </div>
          </div>

          <div class="card">
            <h3>Zero-Trust File Sharing Guard &amp; Verification</h3>
            <p class="sub">Checks extension, MIME, magic bytes, and 20 MiB cap before chunked encryption.</p>
            <div class="field">
              <label for="file-picker">Select Media/Document File (&le; 20 MiB)</label>
              <input id="file-picker" type="file" />
            </div>
            <div class="btn-row" style="margin-bottom:12px;">
              <button class="btn btn-primary" onclick="uploadAndVerifyFile()">Encrypt &amp; Verify File</button>
              <button class="btn btn-soft" onclick="apiCall('/api/sandbox/file-share/validate', {preset:'valid_png'}, 'msg-out', 'msg-verdict')">Valid PNG</button>
              <button class="btn btn-danger" onclick="apiCall('/api/sandbox/file-share/validate', {preset:'spoofed_exe'}, 'msg-out', 'msg-verdict')">Spoofed EXE</button>
              <button class="btn btn-danger" onclick="apiCall('/api/sandbox/file-share/validate', {preset:'oversized_21mb'}, 'msg-out', 'msg-verdict')">&gt;20 MiB Attack</button>
            </div>
            <div id="msg-verdict" class="verdict-box">
              <div class="verdict-title">Checks ready</div>
              <div class="verdict-sub">Send a message, upload a file, or trigger any delivery check.</div>
            </div>
            <details class="raw-json">
              <summary>View Cryptographic Verdict JSON</summary>
              <pre class="console" id="msg-out">Verification output appears here.</pre>
            </details>
          </div>
        </div>

        <div class="card">
          <h3>Encrypted Message Ledger</h3>
          <p class="sub">Delivered envelopes with active suite and ephemeral key erasure confirmation.</p>
          <div style="overflow-x:auto;">
            <table>
              <thead><tr><th>Message / Session ID</th><th>Sender</th><th>Recipient</th><th>Crypto Suite</th><th>Key Erasure</th><th>Latency</th><th>Status</th></tr></thead>
              <tbody id="msg-ledger-tbody">
                <tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:20px;">No envelopes sent yet. Send a protected message above to record one.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- VIEW 4: THREAT DETECTION -->
      <section id="view-threats" class="view-panel">
        <div class="page-head">
          <div>
            <h2>Explainable Threat Detection &amp; Practice Triage</h2>
            <p>Zero AI/ML deterministic rules, lateral-movement DAG, clock-skew ordering, and uploaded CSV timeline evaluation.</p>
          </div>
          <div class="btn-row" style="margin-top:0;">
            <button class="btn btn-primary" onclick="apiCall('/api/sandbox/detector/eval-metrics', {}, 'det-out', 'det-verdict')">Run 550-Event Benchmark</button>
          </div>
        </div>

        <div id="eval-metrics-box" class="grid-4">
          <div class="stat-card"><div class="stat-label">F1 Score</div><div class="stat-value">--</div><div class="stat-meta">Run benchmark to measure</div></div>
          <div class="stat-card"><div class="stat-label">Precision / Recall</div><div class="stat-value">--</div><div class="stat-meta">Labelled scenario set</div></div>
          <div class="stat-card"><div class="stat-label">Median Time to Alert</div><div class="stat-value">--</div><div class="stat-meta">In-memory deterministic eval</div></div>
          <div class="stat-card"><div class="stat-label">False Alerts / 1k Benign Events</div><div class="stat-value">--</div><div class="stat-meta">Benign routine traffic</div></div>
        </div>

        <div class="grid-2">
          <div class="card">
            <h3>Service Lateral Movement DAG &amp; Rule Triggers</h3>
            <p class="sub">Test unauthorized service edges, non-admin rotation attempts, and &plusmn;2000ms out-of-order clock skew.</p>
            <div class="btn-row">
              <button class="btn btn-danger" onclick="apiCall('/api/sandbox/detector/lateral-movement', {}, 'det-out', 'det-verdict')">Lateral Hop (audit &rarr; node-c)</button>
              <button class="btn btn-danger" onclick="apiCall('/api/sandbox/detector/privilege-escalation', {}, 'det-out', 'det-verdict')">Privilege Escalation</button>
              <button class="btn btn-warn" onclick="apiCall('/api/sandbox/detector/clock-skew', {}, 'det-out', 'det-verdict')">Test Clock Skew (&plusmn;2000ms)</button>
            </div>
            <div class="dag-box">
              <svg viewBox="0 0 620 155" width="100%" height="140" xmlns="http://www.w3.org/2000/svg">
                <defs>
                  <marker id="arr-ok" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#16a34a"/></marker>
                  <marker id="arr-bad" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#dc2626"/></marker>
                </defs>
                <line x1="120" y1="42" x2="250" y2="42" stroke="#16a34a" stroke-width="2" marker-end="url(#arr-ok)"/>
                <line x1="120" y1="52" x2="250" y2="112" stroke="#16a34a" stroke-width="2" marker-end="url(#arr-ok)"/>
                <line x1="360" y1="42" x2="485" y2="42" stroke="#16a34a" stroke-width="2" marker-end="url(#arr-ok)"/>
                <line x1="360" y1="112" x2="485" y2="112" stroke="#16a34a" stroke-width="2" marker-end="url(#arr-ok)"/>
                <line x1="485" y1="106" x2="365" y2="52" stroke="#dc2626" stroke-width="2.2" stroke-dasharray="5,4" marker-end="url(#arr-bad)"/>
                <text x="398" y="92" fill="#dc2626" font-size="10" font-family="monospace">BLOCKED LATERAL HOP</text>
                <rect x="16" y="22" width="104" height="38" rx="8" fill="#ffffff" stroke="#2563eb"/><text x="68" y="45" fill="#0f172a" text-anchor="middle" font-size="11.5" font-family="monospace">api-gateway</text>
                <rect x="255" y="22" width="105" height="38" rx="8" fill="#ffffff" stroke="#16a34a"/><text x="307" y="45" fill="#0f172a" text-anchor="middle" font-size="11.5" font-family="monospace">node-c</text>
                <rect x="255" y="94" width="105" height="38" rx="8" fill="#ffffff" stroke="#16a34a"/><text x="307" y="117" fill="#0f172a" text-anchor="middle" font-size="11.5" font-family="monospace">auth-service</text>
                <rect x="490" y="22" width="114" height="38" rx="8" fill="#ffffff" stroke="#2563eb"/><text x="547" y="45" fill="#0f172a" text-anchor="middle" font-size="11.5" font-family="monospace">detector</text>
                <rect x="490" y="94" width="114" height="38" rx="8" fill="#ffffff" stroke="#d97706"/><text x="547" y="117" fill="#92400e" text-anchor="middle" font-size="11.5" font-family="monospace">audit-service</text>
              </svg>
            </div>
            <div id="det-verdict" class="verdict-box" style="margin-top:12px;">
              <div class="verdict-title">Detector ready</div>
              <div class="verdict-sub">Run any trigger above to inspect explainable alerts.</div>
            </div>
            <details class="raw-json">
              <summary>View Detector Telemetry JSON</summary>
              <pre class="console" id="det-out">Detector output appears here.</pre>
            </details>
          </div>

          <div class="card">
            <h3>Live Explainable Security Alerts</h3>
            <p class="sub">Identifies identity, service edge, event IDs, and deterministic rule trigger.</p>
            <div id="alerts-feed" style="max-height:360px;overflow:auto;"></div>
          </div>
        </div>

        <div class="card">
          <h3>
            <span>Upload &amp; Analyze Event Log Files (<code>events.csv</code> + <code>approvals.json</code> + <code>labels.csv</code>)</span>
            <span id="practice-badge" class="badge blue">Ready</span>
          </h3>
          <p class="sub">Separates approved change grants from unexpected role escalation, multi-edge lateral sequences, delayed events, and clock offsets.</p>
          <div class="row-3">
            <div class="field"><label for="prac-events-file">Events CSV (events.csv)</label><input id="prac-events-file" type="file" accept=".csv,.txt" /></div>
            <div class="field"><label for="prac-approvals-file">Approvals JSON (approvals.json)</label><input id="prac-approvals-file" type="file" accept=".json" /></div>
            <div class="field"><label for="prac-labels-file">Labels CSV (optional labels.csv)</label><input id="prac-labels-file" type="file" accept=".csv,.txt" /></div>
          </div>
          <div class="btn-row" style="margin-bottom:12px;">
            <button class="btn btn-primary" onclick="analyzeUploadedPracticeFiles()">Check Uploaded Log Files</button>
            <button class="btn btn-soft" onclick="runPracticeAnalysis(true)">Load Built-In / Local Toolkit Dataset</button>
            <button class="btn" onclick="toggleCustomCsv()">Paste CSV Text</button>
          </div>
          <div id="custom-csv-box" style="display:none;margin-bottom:12px;">
            <div class="grid-2">
              <div class="field"><label>Events CSV</label><textarea id="custom-events-csv"></textarea></div>
              <div class="field"><label>Approvals JSON</label><textarea id="custom-approvals-json">{"changes": []}</textarea></div>
            </div>
            <button class="btn btn-primary" onclick="runPracticeAnalysis(false)">Analyze Pasted Text</button>
          </div>
          <div id="practice-summary" style="margin-bottom:10px;"></div>
          <div style="overflow-x:auto;max-height:340px;">
            <table>
              <thead><tr><th>Event</th><th>Actor</th><th>Service Edge</th><th>Corrected UTC</th><th>Offset</th><th>Classification</th><th>Explanation</th></tr></thead>
              <tbody id="practice-tbody"></tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- VIEW 5: DEVICES, TIMEZONE & AUTHORITY -->
      <section id="view-devices" class="view-panel">
        <div class="page-head">
          <div>
            <h2>Devices, Timezone Policy &amp; Authority Guard</h2>
            <p>Strictly 1 active device per user, cross-timezone session protection, and self-healing rollback for suspicious admin mutations.</p>
          </div>
        </div>

        <div class="grid-2">
          <div class="card">
            <h3>Device Lock &amp; Timezone Enforcement</h3>
            <p class="sub">Bind user device and home timezone, attempt an illegal 2nd device, or test an anomalous geographic timezone jump.</p>
            <div class="row-3">
              <div class="field"><label for="pol-user">User ID</label><input id="pol-user" value="alice" /></div>
              <div class="field"><label for="pol-dev">Device ID</label><input id="pol-dev" value="dev-alice-laptop-01" /></div>
              <div class="field">
                <label for="pol-tz">Timezone</label>
                <select id="pol-tz">
                  <option value="Asia/Kolkata" selected>Asia/Kolkata (Home)</option>
                  <option value="America/New_York">America/New_York (Anomalous)</option>
                  <option value="Europe/London">Europe/London (Anomalous)</option>
                </select>
              </div>
            </div>
            <div class="btn-row">
              <button class="btn btn-primary" onclick="runDeviceTz('register_primary')">Bind Primary Device</button>
              <button class="btn btn-danger" onclick="runSecondDevice()">Attack: Add 2nd Device</button>
              <button class="btn btn-warn" onclick="runDeviceTz('timezone_check')">Test Timezone Access</button>
              <button class="btn" onclick="runDeviceTz('reset')">Reset Policy DB</button>
            </div>

            <hr style="border:none;border-top:1px solid var(--border);margin:16px 0;" />
            <h3>Authority Monitor &amp; Console Snapshot Rollback</h3>
            <div class="row-2">
              <div class="field">
                <label for="auth-action">Console Mutation Action</label>
                <select id="auth-action">
                  <option value="DISABLE_AUDIT">DISABLE_AUDIT (audit_enabled=false)</option>
                  <option value="DISABLE_TIMEZONE_CHECK">DISABLE_TIMEZONE_CHECK</option>
                  <option value="MODIFY_SECURITY_POLICY">Raise Device Cap to 5</option>
                  <option value="BYPASS_POLICY">Raise File Limit to 100 MB</option>
                </select>
              </div>
              <div class="field">
                <label for="auth-role">Monitored Role</label>
                <select id="auth-role"><option value="admin" selected>admin</option><option value="security-operator">security-operator</option></select>
              </div>
            </div>
            <div class="btn-row">
              <button class="btn btn-soft" onclick="runAuthority('grant')">Grant Authority</button>
              <button class="btn" onclick="runAuthority('routine')">Routine Banner Update</button>
              <button class="btn btn-danger" onclick="runAuthority('suspicious')">Attempt Suspicious Edit</button>
            </div>
          </div>

          <div class="card">
            <h3>Live Device, Authority &amp; Console Guard State</h3>
            <div id="id-status-box" style="margin-bottom:10px;"></div>
            <div id="policy-status-box" style="margin-bottom:12px;"></div>
            <div id="pol-verdict" class="verdict-box">
              <div class="verdict-title">Policy state synced</div>
              <div class="verdict-sub">Run any device, timezone, or authority test on the left.</div>
            </div>
            <details class="raw-json">
              <summary>View Policy Response JSON</summary>
              <pre class="console" id="pol-out">Policy output appears here.</pre>
            </details>
          </div>
        </div>
      </section>

      <!-- VIEW 6: KEY MANAGEMENT -->
      <section id="view-keys" class="view-panel">
        <div class="page-head">
          <div>
            <h2>Key Rotation &amp; Cross-Node Revocation</h2>
            <p>Admin control plane for grace-period rotation, hard cutoff enforcement across nodes, rapid revocation broadcast, and device re-enrollment.</p>
          </div>
        </div>

        <div class="grid-2">
          <div class="card">
            <h3>Cluster Key Rotation &amp; Revocation Controls</h3>
            <p class="sub">Authorized transfers continue inside grace; every node rejects expired keys after cutoff and enforces revocations cluster-wide.</p>
            <div class="field">
              <label for="grace-sec">Grace Period Window (Seconds)</label>
              <input id="grace-sec" type="number" step="0.5" min="0.5" max="30" value="3.0" />
            </div>
            <div class="btn-row">
              <button class="btn btn-primary" onclick="apiCall('/api/sandbox/lifecycle/rotate', {grace_seconds: parseFloat(document.getElementById('grace-sec').value || '3')}, 'life-out', 'life-verdict')">1. Rotate Key (Start Grace)</button>
              <button class="btn btn-soft" onclick="apiCall('/api/sandbox/lifecycle/test-old-key', {}, 'life-out', 'life-verdict')">2. Check Old Key (All 3 Nodes)</button>
            </div>
            <div class="btn-row">
              <button class="btn btn-danger" onclick="apiCall('/api/sandbox/lifecycle/revoke-and-reenroll', {mode: 'revoke'}, 'life-out', 'life-verdict')">3. Revoke Alice Key (Measure ms)</button>
              <button class="btn btn-soft" onclick="apiCall('/api/sandbox/lifecycle/revoke-and-reenroll', {mode: 'reenroll'}, 'life-out', 'life-verdict')">4. Re-Enroll New Device</button>
            </div>
          </div>

          <div class="card">
            <h3>Key Lifecycle Verdict &amp; Node State</h3>
            <div id="life-verdict" class="verdict-box">
              <div class="verdict-title">Key lifecycle ready</div>
              <div class="verdict-sub">Rotate a key or trigger cluster revocation to measure timing.</div>
            </div>
            <details class="raw-json" open>
              <summary>View Lifecycle Telemetry JSON</summary>
              <pre class="console" id="life-out">Lifecycle operation results appear here.</pre>
            </details>
          </div>
        </div>
      </section>

      <!-- VIEW 7: AUDIT LOGS -->
      <section id="view-audit" class="view-panel">
        <div class="page-head">
          <div>
            <h2>Tamper-Evident Audit Logs</h2>
            <p>Continuous SHA-256 hash chaining with newline/JSON escape sanitization, 1-byte tamper detection, and exported log file verification.</p>
          </div>
          <span id="audit-badge" class="badge ok">VALID</span>
        </div>

        <div class="grid-2">
          <div class="card">
            <h3>Chain Verification &amp; Upload Checker</h3>
            <div class="btn-row" style="margin-top:0;margin-bottom:12px;">
              <button class="btn btn-primary" onclick="apiCall('/api/sandbox/audit/tamper', {action: 'verify'}, 'audit-out', 'audit-verdict')">Verify Cluster Chain</button>
              <button class="btn btn-warn" onclick="apiCall('/api/sandbox/audit/injection', {}, 'audit-out', 'audit-verdict')">Test Log Injection</button>
              <button class="btn btn-danger" onclick="apiCall('/api/sandbox/audit/tamper', {action: 'tamper'}, 'audit-out', 'audit-verdict')">Mutate 1 Byte</button>
              <button class="btn btn-soft" onclick="apiCall('/api/sandbox/audit/tamper', {action: 'restore'}, 'audit-out', 'audit-verdict')">Restore Clean Chain</button>
            </div>
            <div class="field">
              <label for="audit-file-picker">Upload Audit Log or Adapter State JSON (<code>*.log</code>, <code>*.jsonl</code>, <code>state.json</code>)</label>
              <div style="display:flex;gap:8px;align-items:center;">
                <input id="audit-file-picker" type="file" accept=".log,.jsonl,.json,.txt" />
                <button class="btn btn-primary" style="white-space:nowrap;" onclick="uploadAuditLogFile()">Check File</button>
              </div>
            </div>
          </div>

          <div class="card">
            <h3>Audit Verification Verdict</h3>
            <div id="audit-verdict" class="verdict-box ok">
              <div class="verdict-title">Hash chain verification ready</div>
              <div class="verdict-sub">Run any audit check or upload an exported log file.</div>
            </div>
            <details class="raw-json">
              <summary>View Verification Payload JSON</summary>
              <pre class="console" id="audit-out">Audit verification output appears here.</pre>
            </details>
          </div>
        </div>

        <div class="card">
          <h3>Recent Hash-Chained Events</h3>
          <div style="overflow-x:auto;">
            <table>
              <thead><tr><th>Seq</th><th>Service</th><th>Action</th><th>Actor / Subject</th><th>Status</th><th>Entry Hash</th></tr></thead>
              <tbody id="audit-tbody"></tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- VIEW 8: BACKUP & RECOVERY -->
      <section id="view-recovery" class="view-panel">
        <div class="page-head">
          <div>
            <h2>Crash Recovery &amp; Signed Backup Integrity</h2>
            <p>Write-Ahead Log (WAL) crash recovery preserving revocations, plus HMAC-SHA3-512 snapshot verification and corruption rejection.</p>
          </div>
        </div>

        <div class="grid-2">
          <div class="card">
            <h3>WAL &amp; Backup Operations</h3>
            <p class="sub">Simulate an interrupted rotation crash or flip a byte inside a signed key-state snapshot before restore.</p>
            <div class="btn-row">
              <button class="btn btn-warn" onclick="apiCall('/api/sandbox/resilience/crash-recovery', {}, 'rec-out', 'rec-verdict')">Simulate Mid-Rotation Crash (WAL)</button>
              <button class="btn btn-primary" onclick="apiCall('/api/sandbox/resilience/backup', {tamper: false}, 'rec-out', 'rec-verdict')">Create &amp; Verify Backup</button>
              <button class="btn btn-danger" onclick="apiCall('/api/sandbox/resilience/backup', {tamper: true}, 'rec-out', 'rec-verdict')">Corrupt 1 Byte &amp; Restore</button>
            </div>
          </div>
          <div class="card">
            <h3>Recovery Verdict</h3>
            <div id="rec-verdict" class="verdict-box">
              <div class="verdict-title">Resilience suite ready</div>
              <div class="verdict-sub">Run WAL recovery or backup integrity checks on the left.</div>
            </div>
            <details class="raw-json" open>
              <summary>View Recovery Telemetry JSON</summary>
              <pre class="console" id="rec-out">Crash recovery &amp; backup output appears here.</pre>
            </details>
          </div>
        </div>
      </section>

      <!-- VIEW 9: TRACK-4 ADAPTER -->
      <section id="view-adapter" class="view-panel">
        <div class="page-head">
          <div>
            <h2>Track 4 Compatibility Adapter (<code>track4_service.py</code>)</h2>
            <p>Runs per-request JSON subprocess calls directly against the root adapter with ML-KEM-768 + HMAC-SHA256 <code>protected_read</code>.</p>
          </div>
        </div>

        <div class="grid-2">
          <div class="card">
            <h3>Adapter Parameters &amp; Operations</h3>
            <div class="row-3">
              <div class="field"><label for="adp-actor">Actor</label><input id="adp-actor" value="maya" /></div>
              <div class="field"><label for="adp-asset">Asset ID</label><input id="adp-asset" value="brief" /></div>
              <div class="field"><label for="adp-reqid">Request ID</label><input id="adp-reqid" value="req-gui-01" /></div>
            </div>
            <div class="field"><label for="adp-body">Asset Content Body</label><input id="adp-body" value="Classified Track-4 Zero-Trust Brief" /></div>
            <div class="btn-row">
              <button class="btn btn-primary" onclick="runAdapter('full_suite')">Run Full 7-Step Adapter Suite</button>
              <button class="btn btn-soft" onclick="runAdapter('single', 'setup')">Setup</button>
              <button class="btn" onclick="runAdapter('single', 'read')">Read</button>
              <button class="btn btn-soft" onclick="runAdapter('single', 'protected_read')">Protected Read</button>
              <button class="btn btn-danger" onclick="runAdapter('single', 'revoke')">Revoke</button>
              <button class="btn" onclick="runAdapter('single', 'audit')">Audit</button>
            </div>
          </div>
          <div class="card">
            <h3>Adapter Output</h3>
            <div id="adp-verdict" class="verdict-box">
              <div class="verdict-title">Adapter idle</div>
              <div class="verdict-sub">Run the full lost-device + ML-KEM-768 suite or step individually.</div>
            </div>
            <pre class="console" id="adapter-out">Subprocess JSON request &amp; response trace appears here.</pre>
          </div>
        </div>
      </section>

      <!-- VIEW 10: THREAT MODEL & GUIDE -->
      <section id="view-guide" class="view-panel">
        <div class="page-head">
          <div>
            <h2>Threat Model &amp; CLI Quickstart</h2>
            <p>Protected assets, adversaries, honest constraints, and reproducible terminal commands.</p>
          </div>
        </div>

        <div class="card" style="margin-bottom:16px;">
          <h3>Reproducible CLI Verification Commands (inside <code>.venv</code>)</h3>
          <div class="cmd-line"><code>python -m src.cli demo-replay &amp;&amp; python -m src.cli demo-forward-secrecy</code><button class="btn" onclick="copyText('python -m src.cli demo-replay && python -m src.cli demo-forward-secrecy')">Copy</button></div>
          <div class="cmd-line"><code>python -m src.cli demo-chunked-loss &amp;&amp; python -m src.cli demo-resumption-binding</code><button class="btn" onclick="copyText('python -m src.cli demo-chunked-loss && python -m src.cli demo-resumption-binding')">Copy</button></div>
          <div class="cmd-line"><code>python -m src.cli verify-logs &amp;&amp; python -m src.cli doc-check</code><button class="btn" onclick="copyText('python -m src.cli verify-logs && python -m src.cli doc-check')">Copy</button></div>
          <div class="cmd-line"><code>python ../Track-4-Toolkit/validate.py --entry ./track4_service.py</code><button class="btn" onclick="copyText('python ../Track-4-Toolkit/validate.py --entry ./track4_service.py')">Copy</button></div>
          <div class="cmd-line"><code>pytest tests/ -v</code><button class="btn" onclick="copyText('pytest tests/ -v')">Copy</button></div>
        </div>

        <div class="grid-2">
          <div class="card">
            <h3>Protected Assets &amp; Threat Actors</h3>
            <div class="kv"><span>Payloads</span><span>AES-256-GCM + Recipient AAD</span></div>
            <div class="kv"><span>Identity Keys</span><span>ML-DSA-65 / Dual ML-DSA-87 + SLH-DSA</span></div>
            <div class="kv"><span>Session Secrets</span><span>X25519 + ML-KEM-768 (+ HQC-256)</span></div>
            <div class="kv"><span>File Shares &amp; Devices</span><span>20 MiB + Magic Bytes + 1 Device/User</span></div>
            <div class="kv"><span>Key State &amp; Backups</span><span>Fsynced WAL + HMAC-SHA3-512</span></div>
            <div class="kv"><span>Audit &amp; Config</span><span>SHA-256 Chain + Authority Rollback</span></div>
          </div>
          <div class="card">
            <h3>Assumptions &amp; Honest Limits</h3>
            <ul style="color:var(--text-secondary);padding-left:18px;font-size:13px;line-height:1.65;margin:6px 0 0;">
              <li><strong>Zero AI/ML:</strong> Deterministic O(1) graph edges &amp; context rules; zero black-box drift.</li>
              <li><strong>Clock Skew (&plusmn;2000ms):</strong> Ordered inside window; extreme skew flagged without dropping records.</li>
              <li><strong>Python Memory Zeroization:</strong> Uses best-effort mutable bytearray wiping rather than native mlock/HSM enclaves.</li>
              <li><strong>Single-Host SQLite/WAL:</strong> Durable host storage (<code>TRACK4_STATE_DIR</code>) required for production persistence.</li>
            </ul>
          </div>
        </div>
      </section>

    </main>
  </div>
</div>

<script>
const VIEW_TITLES = {
  dashboard: 'Dashboard',
  tests: 'Test Files & Suites',
  messaging: 'Secure Messaging',
  threats: 'Threat Detection',
  devices: 'Devices & Authority',
  keys: 'Key Management',
  audit: 'Audit Logs',
  recovery: 'Backup & Recovery',
  adapter: 'Track-4 Adapter',
  guide: 'Threat Model & Guide',
};

const SEARCH_SHORTCUTS = [
  {view: 'dashboard', title: 'Dashboard', sub: 'Cluster status, 12-objective verification checklist'},
  {view: 'tests', title: 'Test Files & Suites', sub: 'Upload events.csv / logs / test files, run pytest & validate.py'},
  {view: 'messaging', title: 'Secure Messaging & File Guard', sub: 'PQC v1/v2-paranoid envelopes, 20 MiB magic-byte upload'},
  {view: 'threats', title: 'Threat Detection', sub: 'Lateral DAG, clock skew, F1 benchmark, CSV log upload'},
  {view: 'devices', title: 'Devices & Authority', sub: '1-device lock, timezone anomaly check, admin rollback'},
  {view: 'keys', title: 'Key Management (Admin)', sub: 'Atomic rotation, grace cutoff, cluster revocation, re-enroll'},
  {view: 'audit', title: 'Audit Logs', sub: 'SHA-256 chain verification, log injection, upload .log check'},
  {view: 'recovery', title: 'Backup & Recovery (Admin)', sub: 'WAL crash recovery, HMAC-SHA3-512 backup tamper check'},
  {view: 'adapter', title: 'Track-4 Adapter', sub: 'track4_service.py ML-KEM-768 protected_read runner'},
  {view: 'guide', title: 'Threat Model & Guide', sub: 'Architecture limits and CLI quickstart commands'},
];

let latestState = null;

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function copyText(txt) {
  if (navigator.clipboard) navigator.clipboard.writeText(txt);
}

function getSession() {
  try {
    const raw = sessionStorage.getItem('tbv_session');
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function applySessionUI(sess) {
  const login = document.getElementById('login-screen');
  const shell = document.getElementById('app-shell');
  if (!sess) {
    login.style.display = 'flex';
    shell.classList.remove('visible');
    return;
  }
  login.style.display = 'none';
  shell.classList.add('visible');

  const isAdmin = sess.role === 'ADMIN';
  document.getElementById('sb-avatar').textContent = (sess.username || 'TB').slice(0, 2).toUpperCase();
  document.getElementById('sb-name').textContent = sess.display_name || sess.username;
  document.getElementById('sb-email').textContent = sess.email || (sess.username + '@tbv.local');
  const rb = document.getElementById('hdr-role-badge');
  rb.textContent = sess.role;
  rb.className = 'badge ' + (isAdmin ? 'blue' : 'ok');

  document.querySelectorAll('.nav-btn[data-admin="true"]').forEach(b => {
    b.classList.toggle('hidden-role', !isAdmin);
  });

  const activeBtn = document.querySelector('.nav-btn.active');
  if (activeBtn && activeBtn.classList.contains('hidden-role')) {
    goView('dashboard');
  }
  refreshState();
  loadRepoTests();
}

async function quickSignIn(username, role) {
  document.getElementById('login-username').value = username;
  document.getElementById('login-role').value = role;
  await doLogin(username, role);
}

async function submitLoginForm(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value || 'admin';
  const role = document.getElementById('login-role').value || 'ADMIN';
  await doLogin(username, role);
}

async function doLogin(username, role) {
  const btn = document.getElementById('btn-signin');
  btn.disabled = true;
  btn.textContent = 'Signing in...';
  try {
    const res = await fetch('/api/sandbox/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username, role})
    });
    const sess = await res.json();
    sessionStorage.setItem('tbv_session', JSON.stringify(sess));
    applySessionUI(sess);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign In to Console';
  }
}

async function signOut() {
  const sess = getSession();
  try {
    await fetch('/api/sandbox/auth/logout', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: sess ? sess.token : ''})
    });
  } catch {}
  sessionStorage.removeItem('tbv_session');
  applySessionUI(null);
}

function openAccountSwitcher() {
  signOut();
}

function goView(viewId) {
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const panel = document.getElementById('view-' + viewId);
  const btn = document.querySelector(`.nav-btn[data-view="${viewId}"]`);
  if (panel) panel.classList.add('active');
  if (btn) btn.classList.add('active');
  document.getElementById('topbar-title').textContent = VIEW_TITLES[viewId] || 'Console';
  document.getElementById('sidebar').classList.remove('mobile-open');
  document.getElementById('search-dropdown').classList.remove('open');
}

function onGlobalSearch() {
  const inp = document.getElementById('global-search');
  const dd = document.getElementById('search-dropdown');
  const q = (inp.value || '').trim().toLowerCase();
  if (!q) { dd.classList.remove('open'); return; }

  const sess = getSession();
  const isAdmin = !sess || sess.role === 'ADMIN';
  const hits = [];
  SEARCH_SHORTCUTS.forEach(s => {
    if (!isAdmin && (s.view === 'keys' || s.view === 'recovery')) return;
    if ((s.title + ' ' + s.sub).toLowerCase().includes(q)) hits.push(s);
  });
  if (latestState && Array.isArray(latestState.nodes)) {
    latestState.nodes.forEach(n => {
      if ((n.node_id + ' ' + (n.active_key_id || '')).toLowerCase().includes(q)) {
        hits.push({view: 'dashboard', title: `Node ${n.node_id}`, sub: `Active key ${n.active_key_id || 'NONE'}`});
      }
    });
  }
  if (!hits.length) {
    dd.innerHTML = '<div style="padding:10px 12px;color:var(--text-muted);font-size:12px;">No matching views or nodes found.</div>';
  } else {
    dd.innerHTML = hits.slice(0, 8).map(h => `
      <button type="button" class="search-hit" onclick="goView('${esc(h.view)}')">
        <strong>${esc(h.title)}</strong>
        <span>${esc(h.sub)}</span>
      </button>
    `).join('');
  }
  dd.classList.add('open');
}

document.addEventListener('click', e => {
  const sw = document.getElementById('search-wrap');
  if (sw && !sw.contains(e.target)) {
    document.getElementById('search-dropdown').classList.remove('open');
  }
});

function setVerdict(boxId, data) {
  const box = document.getElementById(boxId);
  if (!box || !data) return;
  let cls = 'verdict-box';
  let title = 'Completed';
  let sub = '';
  if (data.blocked) {
    cls += ' blocked';
    title = 'BLOCKED &mdash; Security Policy Enforced';
    sub = data.detail || data.error_type || data.reason || 'Attack or policy violation denied cleanly';
  } else if (data.ok === false || data.is_valid === false) {
    cls += ' bad';
    title = 'Verification Alert / Failure';
    sub = data.first_error || data.detail || 'Review details below';
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
    sub = parts.join(' | ') || (data.detail || 'Completed and audit-logged cleanly');
  }
  box.className = cls;
  box.innerHTML = '<div class="verdict-title">' + title + '</div><div class="verdict-sub">' + esc(sub) + '</div>';
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
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body || {})
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

// ── Test Files & Suites ──
let queuedBundleFiles = [];
const dz = document.getElementById('bundle-dropzone');
if (dz) {
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
  dz.addEventListener('drop', e => {
    e.preventDefault();
    dz.classList.remove('drag');
    if (e.dataTransfer && e.dataTransfer.files) handleBundleFiles(e.dataTransfer.files);
  });
}

function handleBundleFiles(fileList) {
  queuedBundleFiles = Array.from(fileList || []);
  document.getElementById('bundle-chips').innerHTML = queuedBundleFiles.map(
    f => `<span class="file-chip">${esc(f.name)} (${f.size} B)</span>`
  ).join('');
  if (queuedBundleFiles.length) checkSelectedBundle();
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
  const items = [];
  for (const file of queuedBundleFiles) {
    const buf = await file.arrayBuffer();
    items.push({filename: file.name, mime_type: file.type || null, content_b64: bytesToB64(new Uint8Array(buf))});
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
    detail: `Checked ${s.total_files} file(s): ${s.passed} passed, ${s.blocked_or_failed} blocked/failed`
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
    document.getElementById('repo-tests-meta').textContent = `${files.length} suites | toolkit=${data.toolkit_available ? 'ready' : 'absent'}`;
    document.getElementById('repo-tests-list').innerHTML = files.map(t => `
      <div class="test-item">
        <label><input type="checkbox" class="repo-test-chk" value="${esc(t.name)}" /> <span>tests/${esc(t.name)}</span></label>
        <span style="color:var(--text-muted);">${t.size_bytes} B</span>
      </div>
    `).join('');
  } catch {}
}

function toggleAllTests(checked) {
  document.querySelectorAll('.repo-test-chk').forEach(cb => { cb.checked = checked; });
}

async function executeRepoTestRun(payload) {
  const badge = document.getElementById('bundle-status-badge');
  badge.className = 'badge warn';
  badge.textContent = 'Running...';
  document.getElementById('bundle-results-wrap').innerHTML = '';
  document.getElementById('bundle-triage-wrap').innerHTML = '';
  const res = await fetch('/api/sandbox/tests/run', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
  });
  const data = await res.json();
  let txt = '';
  if (data.pytest) txt += `=== PYTEST ===\\n${data.pytest.output}\\n\\n`;
  if (data.toolkit_validator) txt += `=== TRACK-4-TOOLKIT ===\\n${data.toolkit_validator.output}`;
  document.getElementById('bundle-raw-out').textContent = txt || JSON.stringify(data, null, 2);

  badge.className = 'badge ' + (data.ok ? 'ok' : 'bad');
  badge.textContent = data.ok ? `PASS (${data.duration_ms}ms)` : `FAIL (${data.duration_ms}ms)`;
  const parts = [];
  if (data.pytest) parts.push(`pytest: ${data.pytest.counts.passed} passed, ${data.pytest.counts.failed} failed`);
  if (data.toolkit_validator) parts.push(`Track-4-Toolkit: ${data.toolkit_validator.passed ? 'PASS' : 'FAIL'}`);
  setVerdict('bundle-verdict', {ok: data.ok, detail: parts.join(' | ') || data.detail});
  await refreshState();
}

async function runSelectedTests(toolkitOnly) {
  if (toolkitOnly) return executeRepoTestRun({test_files: [], run_pytest: false, include_toolkit_validator: true});
  const selected = Array.from(document.querySelectorAll('.repo-test-chk:checked')).map(c => c.value);
  if (!selected.length) {
    setVerdict('bundle-verdict', {ok: false, detail: 'Select one or more test files, or click Run Full Suite.'});
    return;
  }
  return executeRepoTestRun({test_files: selected, run_pytest: true, include_toolkit_validator: false});
}

async function runAllPytestSuites() {
  return executeRepoTestRun({test_files: [], run_pytest: true, include_toolkit_validator: true});
}

// ── Messaging & Files ──
async function sendTransfer() {
  return apiCall('/api/sandbox/pqc-transfer', {
    sender: document.getElementById('msg-sender').value || 'alice',
    recipient: document.getElementById('msg-recipient').value || 'bob',
    profile: document.getElementById('msg-profile').value || 'v1',
    message: document.getElementById('msg-input').value || ''
  }, 'msg-out', 'msg-verdict');
}

async function runMessagingSuite() {
  await sendTransfer();
  await apiCall('/api/sandbox/attack/replay', {}, 'msg-out', 'msg-verdict');
  await apiCall('/api/sandbox/attack/recipient-swap', {}, 'msg-out', 'msg-verdict');
  await apiCall('/api/sandbox/attack/forward-secrecy', {}, 'msg-out', 'msg-verdict');
  await apiCall('/api/sandbox/attack/session-resumption', {}, 'msg-out', 'msg-verdict');
  await apiCall('/api/sandbox/attack/loss-reorder', {}, 'msg-out', 'msg-verdict');
}

async function uploadAndVerifyFile() {
  const file = document.getElementById('file-picker').files[0];
  if (!file) { setVerdict('msg-verdict', {ok: false, detail: 'Choose a file first.'}); return; }
  if (file.size > 22 * 1024 * 1024) {
    setVerdict('msg-verdict', {ok: true, blocked: true, detail: `Browser pre-check: ${file.name} exceeds 20 MiB limit`});
    return;
  }
  const buf = await file.arrayBuffer();
  return apiCall('/api/sandbox/file-share/validate', {
    filename: file.name, mime_type: file.type || null, content_b64: bytesToB64(new Uint8Array(buf))
  }, 'msg-out', 'msg-verdict');
}

// ── Audit, Policy, Adapter & Practice ──
async function uploadAuditLogFile() {
  const file = document.getElementById('audit-file-picker').files[0];
  if (!file) { setVerdict('audit-verdict', {ok: false, detail: 'Choose an audit.log, .jsonl, or state.json file first.'}); return; }
  const content = await file.text();
  return apiCall('/api/sandbox/audit/verify-file', {filename: file.name, content}, 'audit-out', 'audit-verdict');
}

async function runDeviceTz(mode) {
  return apiCall('/api/sandbox/policy/device-timezone', {
    mode,
    user_id: document.getElementById('pol-user').value || 'alice',
    device_id: document.getElementById('pol-dev').value || 'dev-alice-laptop-01',
    timezone: document.getElementById('pol-tz').value || 'Asia/Kolkata'
  }, 'pol-out', 'pol-verdict');
}

async function runSecondDevice() {
  return apiCall('/api/sandbox/policy/device-timezone', {
    mode: 'second_device',
    user_id: document.getElementById('pol-user').value || 'alice',
    device_id: 'dev-rogue-secondary-02',
    timezone: document.getElementById('pol-tz').value || 'Asia/Kolkata'
  }, 'pol-out', 'pol-verdict');
}

async function runAuthority(mode) {
  return apiCall('/api/sandbox/authority/console-action', {
    mode,
    user_id: document.getElementById('pol-user').value || 'alice',
    role: document.getElementById('auth-role').value || 'admin',
    action: document.getElementById('auth-action').value || 'DISABLE_AUDIT'
  }, 'pol-out', 'pol-verdict');
}

async function runAdapter(mode, op) {
  return apiCall('/api/sandbox/toolkit/adapter-run', {
    mode, op,
    actor: document.getElementById('adp-actor').value || 'maya',
    asset: document.getElementById('adp-asset').value || 'brief',
    body: document.getElementById('adp-body').value || 'Brief',
    request_id: document.getElementById('adp-reqid').value || 'req-gui-01'
  }, 'adapter-out', 'adp-verdict');
}

function toggleCustomCsv() {
  const b = document.getElementById('custom-csv-box');
  b.style.display = b.style.display === 'none' ? 'block' : 'none';
}

function renderPracticeTableInto(containerId, data) {
  const fs = data.findings_summary || {};
  document.getElementById(containerId).innerHTML = `
    <div class="grid-4" style="margin-bottom:8px;">
      <div class="chk-item fail"><span class="mono">Unapproved Escalations</span><div><strong>${esc((fs.unexpected_role_changes || []).join(', ') || '0')}</strong></div></div>
      <div class="chk-item fail"><span class="mono">Lateral Chains</span><div><strong>${esc((fs.lateral_movement_chains || []).join(', ') || '0')}</strong></div></div>
      <div class="chk-item"><span class="mono">Clock Skew Adjusted</span><div><strong>${esc((fs.clock_skew_events || []).join(', ') || '0')}</strong></div></div>
      <div class="chk-item pass"><span class="mono">Label Agreement</span><div><strong>${esc(data.label_matches)}</strong></div></div>
    </div>
    <table>
      <thead><tr><th>Event</th><th>Actor</th><th>Service Edge</th><th>Corrected UTC</th><th>Offset</th><th>Classification</th><th>Explanation</th></tr></thead>
      <tbody>
        ${(data.events || []).map(ev => {
          const cls = ev.classification || 'routine';
          const bCls = cls.includes('unexpected') || cls.includes('lateral') || cls.includes('review') ? 'bad'
            : cls.includes('approved') ? 'ok'
            : cls.includes('clock') || cls.includes('delayed') || cls.includes('isolated') ? 'warn' : 'blue';
          return `<tr><td class="mono">${esc(ev.event_id)}</td><td class="mono">${esc(ev.actor)}</td><td class="mono">${esc(ev.edge)}</td><td class="mono">${esc(ev.corrected_utc)}</td><td class="mono">${esc(ev.offset_ms)}ms</td><td><span class="badge ${bCls}">${esc(cls)}</span></td><td>${esc(ev.explanation)}</td></tr>`;
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
  if (!evFile) { badge.className = 'badge warn'; badge.textContent = 'Select events.csv first'; return; }
  return _runPracticePayload({
    events_csv: await evFile.text(),
    approvals_json: appFile ? await appFile.text() : '{"changes": []}',
    labels_csv: lblFile ? await lblFile.text() : null,
    use_sample: false
  });
}

async function runPracticeAnalysis(useSample) {
  return _runPracticePayload(useSample ? {use_sample: true} : {
    use_sample: false,
    events_csv: document.getElementById('custom-events-csv').value,
    approvals_json: document.getElementById('custom-approvals-json').value
  });
}

async function _runPracticePayload(body) {
  const badge = document.getElementById('practice-badge');
  badge.textContent = 'Analyzing...';
  const res = await fetch('/api/sandbox/detector/practice-events', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!data.ok) { badge.className = 'badge bad'; badge.textContent = data.detail || 'Error'; return; }
  badge.className = 'badge ok';
  badge.textContent = `${data.total_events} events (${data.dataset_source})` + (data.label_matches !== 'no labels.csv provided' ? ` | ${data.label_matches} labels` : '');
  document.getElementById('practice-summary').innerHTML = '';
  renderPracticeTableInto('practice-summary', data);
  document.getElementById('practice-tbody').innerHTML = '';
  await refreshState();
}

async function refreshState() {
  try {
    const res = await fetch('/api/sandbox/state');
    const s = await res.json();
    latestState = s;

    document.getElementById('hdr-pqc').textContent = `${s.crypto.kem_algorithm} + ${s.crypto.sig_algorithm}`;
    document.getElementById('kpi-uptime').textContent = `uptime: ${s.uptime_seconds}s`;
    const activeNodes = (s.nodes || []).filter(n => n.active_key_id).length;
    document.getElementById('kpi-nodes').textContent = `${activeNodes} / ${(s.nodes || []).length}`;

    document.getElementById('kpi-score').textContent = `${s.checklist_passed} / ${s.checklist_total}`;
    document.getElementById('chk-count-lbl').textContent = `${s.checklist_passed} / ${s.checklist_total} Verified`;
    document.getElementById('chk-bar').style.width = ((s.checklist_passed / s.checklist_total) * 100) + '%';

    const chainOk = s.audit.verification && s.audit.verification.is_valid;
    document.getElementById('kpi-chain').textContent = chainOk ? 'VALID' : 'TAMPERED!';
    document.getElementById('kpi-chain').style.color = chainOk ? 'var(--green-text)' : 'var(--red-text)';
    document.getElementById('kpi-records').textContent = `${s.audit.verification.total_records || 0} hash-chained records`;
    const auditBadge = document.getElementById('audit-badge');
    auditBadge.textContent = chainOk ? `VALID (${s.audit.verification.total_records} records)` : `TAMPERED (seq ${s.audit.verification.corrupted_sequence})`;
    auditBadge.className = 'badge ' + (chainOk ? 'ok' : 'bad');

    const ps = s.policy_state || {};
    const cs = ps.console_state || {};
    document.getElementById('kpi-policy').textContent = `${ps.max_file_size_mb || 20} MiB / ${ps.max_devices_per_user || 1} Dev`;

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

    const ml = s.message_ledger || [];
    document.getElementById('msg-kpi-count').textContent = String(ml.length);
    document.getElementById('msg-kpi-wiped').textContent = String(ml.filter(x => x.ephemeral_wiped).length);
    if (ml.length > 0) {
      document.getElementById('msg-ledger-tbody').innerHTML = ml.map(m => `
        <tr>
          <td class="mono">${esc((m.id || '').slice(0, 18))}...</td>
          <td>${esc(m.sender)}</td>
          <td>${esc(m.recipient)}</td>
          <td class="mono">${esc(m.suite)}</td>
          <td><span class="badge ok">${m.ephemeral_wiped ? 'WIPED' : 'ACTIVE'}</span></td>
          <td class="mono">${esc(m.latency_ms)} ms</td>
          <td><span class="badge ok">${esc(m.status)}</span></td>
        </tr>
      `).join('');
    }

    const al = s.identities.alice;
    const bo = s.identities.bob;
    document.getElementById('id-status-box').innerHTML = `
      <div class="kv"><span>Alice (${esc(al.device_id)})</span><span class="badge ${al.status === 'active' ? 'ok' : 'bad'}">${esc(al.status.toUpperCase())}</span></div>
      <div class="kv"><span>Bob (${esc(bo.device_id)})</span><span class="badge ok">ACTIVE</span></div>
      <div class="kv"><span>Last Revocation Latency</span><span class="mono">${s.revocation_propagation_ms !== null ? esc(s.revocation_propagation_ms) + ' ms' : 'Not measured yet'}</span></div>
    `;

    const devRows = (ps.devices || []).map(d => `<div class="kv"><span>${esc(d.user_id)} / ${esc(d.device_id)}</span><span class="badge ${d.status === 'active' ? 'ok' : 'bad'}">${esc(d.status)} @ ${esc(d.home_timezone)}</span></div>`).join('');
    const authRows = (ps.authorities || []).map(a => `<div class="kv"><span>Authority: ${esc(a.user_id)} (${esc(a.role)})</span><span class="badge ${a.status === 'active' && !a.has_active_threat ? 'ok' : 'bad'}">${esc(a.status.toUpperCase())}${a.has_active_threat ? ' [' + esc(a.last_threat_case) + ']' : ''}</span></div>`).join('');
    document.getElementById('policy-status-box').innerHTML = `
      <div class="kv"><span>Console Snapshot Digest</span><span class="mono">${esc((ps.console_state_hash || '').slice(0, 18))}...</span></div>
      <div class="kv"><span>Audit Lock / Timezone Check</span><span class="badge blue">${esc(cs.audit_enabled)} / ${esc(cs.timezone_check_enabled)}</span></div>
      ${devRows}
      ${authRows}
    `;

    document.getElementById('audit-tbody').innerHTML = (s.audit.recent_entries || []).map(r => `
      <tr>
        <td class="mono">${esc(r.sequence ?? '-')}</td>
        <td class="mono">${esc(r.service || '-')}</td>
        <td class="mono">${esc(r.action || '-')}</td>
        <td class="mono">${esc((r.subject || '-').slice(0, 38))}</td>
        <td><span class="badge ${r.status === 'SUCCESS' ? 'ok' : 'bad'}">${esc(r.status || '-')}</span></td>
        <td class="mono" style="color:var(--blue-text);">${esc((r.entry_hash || '').slice(0, 16))}...</td>
      </tr>
    `).join('');

    const alerts = s.alerts || [];
    document.getElementById('alerts-feed').innerHTML = alerts.length === 0
      ? '<p class="sub">No security alerts recorded yet. Run any simulation on the left to trigger alerts.</p>'
      : alerts.map(a => `
        <div class="alert-card ${esc(a.severity || 'HIGH')}">
          <div style="display:flex;justify-content:space-between;font-weight:700;font-size:12.5px;">
            <span>[${esc(a.severity || 'HIGH')}] ${esc(a.rule_name)}</span>
            <span class="mono">${esc(a.service || '')}</span>
          </div>
          <div style="font-size:12.5px;margin:4px 0;">${esc(a.description || '')}</div>
          <div class="mono" style="font-size:11px;color:var(--text-muted);">Subject: ${esc(a.subject || '-')}</div>
        </div>
      `).join('');

    if (s.eval_metrics) {
      const m = s.eval_metrics;
      document.getElementById('eval-metrics-box').innerHTML = `
        <div class="stat-card"><div class="stat-label">F1 Score</div><div class="stat-value" style="color:var(--green-text);">${esc(m.f1_score)}</div><div class="stat-meta">Target &ge; 0.90</div></div>
        <div class="stat-card"><div class="stat-label">Precision / Recall</div><div class="stat-value">${esc(m.precision)} / ${esc(m.recall)}</div><div class="stat-meta">550 labelled events</div></div>
        <div class="stat-card"><div class="stat-label">Median Alert Latency</div><div class="stat-value">${esc(m.median_time_to_alert_ms)} ms</div><div class="stat-meta">Zero AI/ML engine</div></div>
        <div class="stat-card"><div class="stat-label">False Alerts / 1k Benign Events</div><div class="stat-value">${esc(m.false_alerts_per_1k)}</div><div class="stat-meta">Routine traffic</div></div>
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
    await apiCall('/api/sandbox/pqc-transfer', {message: 'Auto Wire #101', profile: 'v1'}, 'msg-out', 'msg-verdict');
    await apiCall('/api/sandbox/pqc-transfer', {message: 'Paranoid Wire #102', profile: 'v2-paranoid'}, 'msg-out', 'msg-verdict');
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
    await apiCall('/api/sandbox/resilience/crash-recovery', {}, 'rec-out', 'rec-verdict');
    await apiCall('/api/sandbox/resilience/backup', {tamper: false}, 'rec-out', 'rec-verdict');
    await apiCall('/api/sandbox/resilience/backup', {tamper: true}, 'rec-out', 'rec-verdict');
    await apiCall('/api/sandbox/policy/device-timezone', {mode: 'second_device', user_id: 'alice', device_id: 'dev-rogue-2', timezone: 'Asia/Kolkata'}, 'pol-out', 'pol-verdict');
    await apiCall('/api/sandbox/authority/console-action', {mode: 'suspicious', user_id: 'alice', role: 'admin', action: 'DISABLE_AUDIT'}, 'pol-out', 'pol-verdict');
    await apiCall('/api/sandbox/audit/injection', {}, 'audit-out', 'audit-verdict');
    await apiCall('/api/sandbox/toolkit/adapter-run', {mode: 'full_suite'}, 'adapter-out', 'adp-verdict');
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

applySessionUI(getSession());
setInterval(() => { if (getSession()) refreshState(); }, 4000);
</script>
</body>
</html>
"""
