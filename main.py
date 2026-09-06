#pyt#!/usr/bin/env python3.
#this is a website for checking another websites vulnerabilities 🙃🙂
#hope you guys don't misuse of this 😵‍💫
"""
WebSentry - Fast Website Vulnerability Scanner
Run: python scanner.py
Opens on: http://localhost:5000
"""
import os
import asyncio
import aiohttp
import ssl
import socket
import re
import json
import time
import threading
from urllib.parse import urlparse, urljoin, quote
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, Response
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings("ignore")

app = Flask(__name__)

# ─────────────────────────────────────────────
# HTML TEMPLATE
# ─────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebSentry — Vulnerability Scanner</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root {
    --bg: #080c10;
    --panel: #0d1117;
    --border: #21262d;
    --green: #39d353;
    --green-dim: #1a4025;
    --red: #f85149;
    --red-dim: #3d1a1a;
    --yellow: #e3b341;
    --yellow-dim: #3d2e10;
    --blue: #58a6ff;
    --blue-dim: #0d2044;
    --gray: #8b949e;
    --text: #c9d1d9;
    --mono: 'Share Tech Mono', monospace;
    --sans: 'Rajdhani', sans-serif;
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
}

/* Grid background */
body::before {
    content:'';
    position:fixed; inset:0;
    background-image:
        linear-gradient(rgba(57,211,83,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(57,211,83,.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events:none; z-index:0;
}

.container { max-width:1100px; margin:0 auto; padding:0 20px; position:relative; z-index:1; }

/* Header */
header {
    border-bottom: 1px solid var(--border);
    padding: 18px 0;
    margin-bottom: 40px;
}
.header-inner { display:flex; align-items:center; gap:14px; }
.logo-icon {
    width:40px; height:40px;
    border:2px solid var(--green);
    border-radius:8px;
    display:flex; align-items:center; justify-content:center;
    font-family:var(--mono); color:var(--green); font-size:18px;
    box-shadow: 0 0 12px rgba(57,211,83,.3);
    animation: pulse-border 2s ease-in-out infinite;
}
@keyframes pulse-border {
    0%,100% { box-shadow: 0 0 12px rgba(57,211,83,.3); }
    50%      { box-shadow: 0 0 24px rgba(57,211,83,.6); }
}
.logo-text { font-size:24px; font-weight:700; letter-spacing:2px; }
.logo-text span { color:var(--green); }
.tagline { font-family:var(--mono); font-size:20px; color:var(--gray); margin-top:2px; }
.badge {
    margin-left:auto;
    background:var(--green-dim);
    border:1px solid var(--green);
    color:var(--green);
    font-family:var(--mono); font-size:10px;
    padding:4px 10px; border-radius:4px;
    letter-spacing:1px;
}

/* Scan form */
.scan-box {
    background:var(--panel);
    border:1px solid var(--border);
    border-radius:12px;
    padding:28px;
    margin-bottom:28px;
}
.scan-box h2 {
    font-size:14px; font-family:var(--mono);
    color:var(--gray); text-transform:uppercase;
    letter-spacing:2px; margin-bottom:18px;
}
.input-row { display:flex; gap:12px; }
.url-input {
    flex:1;
    background: #010409;
    border:1px solid var(--border);
    border-radius:8px;
    padding:12px 16px;
    color:var(--text);
    font-family:var(--mono);
    font-size:14px;
    outline:none;
    transition: border-color .2s, box-shadow .2s;
}
.url-input:focus {
    border-color:var(--green);
    box-shadow: 0 0 0 3px rgba(57,211,83,.1);
}
.scan-btn {
    background: var(--green);
    color: #000;
    border:none; border-radius:8px;
    padding:12px 28px;
    font-family:var(--sans); font-weight:700;
    font-size:15px; letter-spacing:1px;
    cursor:pointer;
    transition: all .2s;
    white-space:nowrap;
}
.scan-btn:hover { background:#4dff70; transform:translateY(-1px); }
.scan-btn:disabled { background:#1a4025; color:#39d353; cursor:not-allowed; transform:none; }

/* Checks grid */
.checks-grid {
    display:grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap:8px; margin-top:16px;
}
.check-chip {
    background:#010409;
    border:1px solid var(--border);
    border-radius:6px;
    padding:6px 10px;
    font-family:var(--mono); font-size:11px;
    color:var(--gray);
    display:flex; align-items:center; gap:6px;
}
.check-chip .dot {
    width:6px; height:6px; border-radius:50%;
    background:var(--gray); flex-shrink:0;
    transition: background .3s;
}
.check-chip.running .dot { background:var(--blue); animation:blink .6s infinite; }
.check-chip.done    .dot { background:var(--green); }
.check-chip.warn    .dot { background:var(--yellow); }
.check-chip.danger  .dot { background:var(--red); }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.3} }

/* Progress */
.progress-wrap { margin-top:16px; display:none; }
.progress-bar-track {
    height:4px; background:var(--border); border-radius:2px; overflow:hidden;
}
.progress-bar-fill {
    height:100%; background:var(--green);
    border-radius:2px; width:0;
    transition:width .4s ease;
    box-shadow:0 0 8px var(--green);
}
.progress-label {
    font-family:var(--mono); font-size:11px;
    color:var(--gray); margin-top:6px;
}

/* Results */
#results { display:none; }
.results-header {
    display:flex; align-items:center; gap:12px;
    margin-bottom:20px; flex-wrap:wrap;
}
.results-header h2 {
    font-size:18px; font-weight:700; letter-spacing:1px;
}
.score-badge {
    padding:4px 14px; border-radius:20px;
    font-family:var(--mono); font-size:13px; font-weight:700;
}
.score-safe   { background:var(--green-dim); color:var(--green); border:1px solid var(--green); }
.score-warn   { background:var(--yellow-dim); color:var(--yellow); border:1px solid var(--yellow); }
.score-danger { background:var(--red-dim); color:var(--red); border:1px solid var(--red); }

.summary-grid {
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:12px; margin-bottom:24px;
}
@media(max-width:600px){ .summary-grid{ grid-template-columns:repeat(2,1fr); } }
.stat-card {
    background:var(--panel);
    border:1px solid var(--border);
    border-radius:10px; padding:16px;
    text-align:center;
}
.stat-card .num { font-size:32px; font-weight:700; font-family:var(--mono); }
.stat-card .lbl { font-size:11px; color:var(--gray); margin-top:4px; text-transform:uppercase; letter-spacing:1px; }
.num-critical { color:var(--red); }
.num-warn     { color:var(--yellow); }
.num-info     { color:var(--blue); }
.num-ok       { color:var(--green); }

/* Vuln cards */
.vuln-section { margin-bottom:28px; }
.section-title {
    font-family:var(--mono); font-size:11px;
    text-transform:uppercase; letter-spacing:2px;
    color:var(--gray); margin-bottom:12px;
    padding-bottom:8px; border-bottom:1px solid var(--border);
}
.vuln-card {
    background:var(--panel);
    border:1px solid var(--border);
    border-left:3px solid;
    border-radius:8px; padding:16px;
    margin-bottom:10px;
    transition: transform .15s;
}
.vuln-card:hover { transform:translateX(3px); }
.vuln-card.critical { border-left-color:var(--red); }
.vuln-card.warning  { border-left-color:var(--yellow); }
.vuln-card.info     { border-left-color:var(--blue); }
.vuln-card.safe     { border-left-color:var(--green); }
.card-top { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; }
.card-name { font-weight:700; font-size:15px; }
.sev-pill {
    font-family:var(--mono); font-size:10px;
    padding:3px 8px; border-radius:4px;
    flex-shrink:0; letter-spacing:1px;
}
.pill-critical { background:var(--red-dim); color:var(--red); }
.pill-warning  { background:var(--yellow-dim); color:var(--yellow); }
.pill-info     { background:var(--blue-dim); color:var(--blue); }
.pill-safe     { background:var(--green-dim); color:var(--green); }
.card-desc { font-size:13px; color:var(--gray); margin-top:6px; line-height:1.5; }
.card-detail {
    margin-top:10px; padding:10px;
    background:#010409; border-radius:6px;
    font-family:var(--mono); font-size:11px;
    color:var(--text); word-break:break-all; line-height:1.6;
}

/* Log terminal */
.terminal {
    background:#010409;
    border:1px solid var(--border);
    border-radius:10px; padding:16px;
    font-family:var(--mono); font-size:12px;
    height:200px; overflow-y:auto;
    margin-bottom:24px;
}
.log-line { line-height:1.8; }
.log-line.ok   { color:var(--green); }
.log-line.warn { color:var(--yellow); }
.log-line.err  { color:var(--red); }
.log-line.info { color:var(--blue); }
.log-line.gray { color:var(--gray); }

.footer {
    text-align:center; padding:28px 0;
    font-family:var(--mono); font-size:11px;
    color:#3a4552; border-top:1px solid var(--border);
    margin-top:40px;
}
</style>
</head>
<body>
<div class="container">

<header>
    <div class="header-inner">
        <div class="logo-icon">⚡</div>
        <div>
            <div class="logo-text">Web<span>Sentry</span></div>
            <div class="tagline">// fast vulnerability scanner — ~Made by :- <strong style="color: green; font-size: 20px;">Dipak Kumar Maurya</strong></div>
        </div>
        <div class="badge">v1.0 BETA</div>
    </div>
</header>

<!-- Scan Form -->
<div class="scan-box">
    <h2>// Target Configuration</h2>
    <div class="input-row">
        <input class="url-input" id="urlInput" type="text"
            placeholder="https://example.com" value="https://">
        <button class="scan-btn" id="scanBtn" onclick="startScan()">▶ SCAN</button>
    </div>

    <div class="checks-grid" id="checksGrid">
        <!-- filled by JS -->
    </div>

    <div class="progress-wrap" id="progressWrap">
        <div class="progress-bar-track">
            <div class="progress-bar-fill" id="progressFill"></div>
        </div>
        <div class="progress-label" id="progressLabel">Initializing...</div>
    </div>
</div>

<!-- Terminal Log -->
<div class="terminal" id="terminal" style="display:none">
    <div class="log-line gray">// WebSentry ready. Enter a URL and press SCAN.</div>
</div>

<!-- Results -->
<div id="results">
    <div class="results-header">
        <h2>Scan Report</h2>
        <span id="scoreBadge" class="score-badge">—</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--gray);margin-left:auto" id="scanMeta"></span>
    </div>

    <div class="summary-grid">
        <div class="stat-card"><div class="num num-critical" id="cntCritical">0</div><div class="lbl">Critical</div></div>
        <div class="stat-card"><div class="num num-warn"     id="cntWarning">0</div><div class="lbl">Warning</div></div>
        <div class="stat-card"><div class="num num-info"     id="cntInfo">0</div><div class="lbl">Info</div></div>
        <div class="stat-card"><div class="num num-ok"       id="cntSafe">0</div><div class="lbl">Passed</div></div>
    </div>

    <div class="vuln-section" id="criticalSection" style="display:none">
        <div class="section-title">🔴 Critical Findings</div>
        <div id="criticalCards"></div>
    </div>
    <div class="vuln-section" id="warningSection" style="display:none">
        <div class="section-title">🟡 Warnings</div>
        <div id="warningCards"></div>
    </div>
    <div class="vuln-section" id="infoSection" style="display:none">
        <div class="section-title">🔵 Information</div>
        <div id="infoCards"></div>
    </div>
    <div class="vuln-section" id="safeSection" style="display:none">
        <div class="section-title">🟢 Passed Checks</div>
        <div id="safeCards"></div>
    </div>
</div>

<div class="footer">WebSentry — Educational Use Only &nbsp;|&nbsp; Do not scan sites without permission</div>
</div>

<script>
const CHECKS = [
    "SSL/TLS","Headers","Cookies","XSS","SQLi",
    "Open Dirs","CORS","Info Leak","Ports","Robots",
    "Clickjack","CSRF","Redirects","DNS","Forms"
];

let chipEls = {};

function buildChips() {
    const grid = document.getElementById('checksGrid');
    grid.innerHTML = '';
    CHECKS.forEach(c => {
        const el = document.createElement('div');
        el.className = 'check-chip';
        el.id = 'chip_' + c.replace(/[^a-z]/gi,'');
        el.innerHTML = `<span class="dot"></span>${c}`;
        grid.appendChild(el);
        chipEls[c] = el;
    });
}

function setChip(name, state) {
    const el = document.getElementById('chip_' + name.replace(/[^a-z]/gi,''));
    if (el) el.className = 'check-chip ' + state;
}

function log(msg, cls='gray') {
    const t = document.getElementById('terminal');
    const ts = new Date().toLocaleTimeString('en-GB',{hour12:false});
    const line = document.createElement('div');
    line.className = 'log-line ' + cls;
    line.textContent = `[${ts}] ${msg}`;
    t.appendChild(line);
    t.scrollTop = t.scrollHeight;
}

function setProgress(pct, label) {
    document.getElementById('progressFill').style.width = pct + '%';
    document.getElementById('progressLabel').textContent = label;
}

async function startScan() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url || url === 'https://') { alert('Please enter a valid URL'); return; }

    // Reset UI
    buildChips();
    document.getElementById('terminal').style.display = 'block';
    document.getElementById('terminal').innerHTML = '';
    document.getElementById('results').style.display = 'none';
    document.getElementById('progressWrap').style.display = 'block';
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('scanBtn').textContent = '⟳ SCANNING';
    setProgress(0, 'Starting scan...');

    log(`Target: ${url}`, 'info');
    log('Initializing WebSentry scanner...', 'gray');

    try {
        const resp = await fetch('/scan', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({url})
        });

        if (!resp.ok) throw new Error('Server error ' + resp.status);

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';

        while (true) {
            const {done, value} = await reader.read();
            if (done) break;
            buf += decoder.decode(value, {stream:true});
            const lines = buf.split('\n');
            buf = lines.pop();
            for (const line of lines) {
                if (!line.trim()) continue;
                try {
                    const evt = JSON.parse(line);
                    handleEvent(evt);
                } catch(e) {}
            }
        }
    } catch(err) {
        log('Error: ' + err.message, 'err');
    }

    document.getElementById('scanBtn').disabled = false;
    document.getElementById('scanBtn').textContent = '▶ SCAN';
}

function handleEvent(evt) {
    if (evt.type === 'log') {
        log(evt.msg, evt.cls || 'gray');
    } else if (evt.type === 'progress') {
        setProgress(evt.pct, evt.label);
        if (evt.check) setChip(evt.check, evt.state || 'running');
    } else if (evt.type === 'done') {
        renderResults(evt.data);
    }
}

function renderResults(data) {
    const findings = data.findings || [];
    let critical=0, warning=0, info=0, safe=0;
    findings.forEach(f => {
        if(f.severity==='critical') critical++;
        else if(f.severity==='warning') warning++;
        else if(f.severity==='info') info++;
        else safe++;
    });

    document.getElementById('cntCritical').textContent = critical;
    document.getElementById('cntWarning').textContent  = warning;
    document.getElementById('cntInfo').textContent     = info;
    document.getElementById('cntSafe').textContent     = safe;

    const score = critical>0?'CRITICAL':warning>3?'HIGH RISK':warning>0?'MODERATE':'SECURE';
    const scoreEl = document.getElementById('scoreBadge');
    scoreEl.textContent = score;
    scoreEl.className = 'score-badge ' + (critical>0||warning>3?'score-danger':warning>0?'score-warn':'score-safe');

    document.getElementById('scanMeta').textContent =
        `Scanned: ${data.url} | Duration: ${data.duration}s | ${new Date().toLocaleString()}`;

    ['critical','warning','info','safe'].forEach(sev => {
        const section = document.getElementById(sev+'Section');
        const container = document.getElementById(sev+'Cards');
        const group = findings.filter(f => f.severity===sev);
        if (group.length) {
            section.style.display='block';
            container.innerHTML = group.map(f => cardHTML(f)).join('');
        } else {
            section.style.display='none';
        }
    });

    document.getElementById('results').style.display = 'block';
    setProgress(100, 'Scan complete!');
    log('✓ Scan complete. ' + findings.length + ' findings.', 'ok');

    // Update chips to final state
    findings.forEach(f => {
        const chipState = f.severity==='critical'?'danger':f.severity==='warning'?'warn':f.severity==='safe'?'done':'running';
        // chips already set during scan
    });
}

function cardHTML(f) {
    const pillClass = {critical:'pill-critical',warning:'pill-warning',info:'pill-info',safe:'pill-safe'}[f.severity]||'pill-info';
    const cardClass = f.severity;
    const detail = f.detail ? `<div class="card-detail">${escHtml(f.detail)}</div>` : '';
    return `
    <div class="vuln-card ${cardClass}">
        <div class="card-top">
            <div class="card-name">${escHtml(f.name)}</div>
            <span class="sev-pill ${pillClass}">${f.severity.toUpperCase()}</span>
        </div>
        <div class="card-desc">${escHtml(f.description)}</div>
        ${detail}
    </div>`;
}

function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

buildChips();
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
# SCANNER ENGINE
# ─────────────────────────────────────────────

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017]
COMMON_DIRS  = [
    "admin", "administrator", "wp-admin", "login", "panel", "dashboard",
    "phpmyadmin", "cpanel", "webmail", "backup", "config", "test",
    "api", ".git", ".env", "server-status", "elmah.axd"
]
XSS_PAYLOADS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "';alert(1)//"]
SQLI_PAYLOADS = ["'", '"', "1' OR '1'='1", "' OR 1=1--", '" OR "1"="1']

def make_finding(name, severity, description, detail=""):
    return {"name": name, "severity": severity, "description": description, "detail": detail}

def emit(gen_queue, evt):
    gen_queue.append(json.dumps(evt) + "\n")

# ── SSL/TLS ────────────────────────────────
def check_ssl(parsed, queue):
    emit(queue, {"type":"progress","pct":5,"label":"Checking SSL/TLS...","check":"SSL/TLS","state":"running"})
    findings = []
    hostname = parsed.hostname

    if parsed.scheme != "https":
        findings.append(make_finding("No HTTPS", "critical",
            "Site is not using HTTPS. Data transmitted in plaintext.",
            "Switch to HTTPS and redirect all HTTP traffic."))
        emit(queue, {"type":"log","msg":"[SSL] No HTTPS detected","cls":"err"})
        emit(queue, {"type":"progress","pct":10,"label":"SSL checked","check":"SSL/TLS","state":"danger"})
        return findings

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        conn.settimeout(5)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        conn.close()

        # Check expiry
        import datetime as dt
        exp = cert.get('notAfter', '')
        if exp:
            exp_dt = dt.datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_dt - dt.datetime.utcnow()).days
            if days_left < 0:
                findings.append(make_finding("SSL Certificate Expired","critical",
                    f"SSL certificate expired {abs(days_left)} days ago.", f"Expires: {exp}"))
                emit(queue,{"type":"log","msg":f"[SSL] Certificate EXPIRED ({days_left} days)","cls":"err"})
            elif days_left < 30:
                findings.append(make_finding("SSL Certificate Expiring Soon","warning",
                    f"SSL certificate expires in {days_left} days.", f"Expiry: {exp}"))
                emit(queue,{"type":"log","msg":f"[SSL] Cert expires in {days_left} days","cls":"warn"})
            else:
                findings.append(make_finding("SSL Certificate Valid","safe",
                    f"Certificate valid for {days_left} more days.", f"Expiry: {exp}"))
                emit(queue,{"type":"log","msg":f"[SSL] Valid cert, {days_left} days left","cls":"ok"})

        # Version check
        ver = conn.version() if hasattr(conn,'version') else "Unknown"
        emit(queue,{"type":"log","msg":f"[SSL] Protocol: {ver}","cls":"info"})

    except ssl.SSLError as e:
        findings.append(make_finding("SSL Error","critical",
            "SSL/TLS handshake failed.", str(e)))
        emit(queue,{"type":"log","msg":f"[SSL] Error: {e}","cls":"err"})
    except Exception as e:
        findings.append(make_finding("SSL Check Failed","info",
            "Could not connect to verify SSL.", str(e)))
        emit(queue,{"type":"log","msg":f"[SSL] Could not check: {e}","cls":"warn"})

    emit(queue,{"type":"progress","pct":12,"label":"SSL checked","check":"SSL/TLS","state":"done"})
    return findings

# ── HTTP HEADERS ───────────────────────────
def check_headers(url, session_headers, queue):
    emit(queue,{"type":"progress","pct":15,"label":"Checking security headers...","check":"Headers","state":"running"})
    findings = []
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent":"WebSentry/1.0"})
        try:
            resp = urllib.request.urlopen(req, timeout=8)
            headers = {k.lower(): v for k,v in resp.headers.items()}
        except Exception:
            resp = None
            headers = {}

        security_headers = {
            "strict-transport-security": ("HSTS Missing","warning",
                "HTTP Strict Transport Security not set. Vulnerable to downgrade attacks."),
            "content-security-policy": ("CSP Missing","warning",
                "Content-Security-Policy not set. XSS attacks harder to mitigate."),
            "x-frame-options": ("X-Frame-Options Missing","warning",
                "Missing X-Frame-Options. Site may be vulnerable to clickjacking."),
            "x-content-type-options": ("X-Content-Type-Options Missing","warning",
                "Missing X-Content-Type-Options: nosniff. MIME sniffing attacks possible."),
            "referrer-policy": ("Referrer-Policy Missing","info",
                "Referrer-Policy header not set."),
            "permissions-policy": ("Permissions-Policy Missing","info",
                "Permissions-Policy not set. Browser features not restricted."),
        }

        for hdr, (name, sev, desc) in security_headers.items():
            if hdr in headers:
                findings.append(make_finding(name.replace("Missing","Present"),"safe",
                    f"{hdr} is properly set.", f"Value: {headers[hdr][:100]}"))
                emit(queue,{"type":"log","msg":f"[HDR] ✓ {hdr} present","cls":"ok"})
            else:
                findings.append(make_finding(name, sev, desc, f"Header '{hdr}' not found in response."))
                emit(queue,{"type":"log","msg":f"[HDR] ✗ {hdr} missing","cls":"warn"})

        # Server header leak
        if "server" in headers:
            sv = headers["server"]
            findings.append(make_finding("Server Header Disclosure","warning",
                "Server header reveals web server software version.",
                f"Server: {sv}"))
            emit(queue,{"type":"log","msg":f"[HDR] Server: {sv}","cls":"warn"})

        # X-Powered-By
        if "x-powered-by" in headers:
            findings.append(make_finding("X-Powered-By Disclosure","warning",
                "X-Powered-By header reveals backend technology.",
                f"X-Powered-By: {headers['x-powered-by']}"))

    except Exception as e:
        emit(queue,{"type":"log","msg":f"[HDR] Error: {e}","cls":"err"})

    emit(queue,{"type":"progress","pct":25,"label":"Headers checked","check":"Headers","state":"done"})
    return findings

# ── COOKIES ────────────────────────────────
def check_cookies(url, queue):
    emit(queue,{"type":"progress","pct":27,"label":"Analyzing cookies...","check":"Cookies","state":"running"})
    findings = []
    try:
        import urllib.request, http.cookiejar
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        opener.addheaders = [("User-Agent","WebSentry/1.0")]
        try: opener.open(url, timeout=8)
        except: pass

        if not jar:
            findings.append(make_finding("No Cookies Found","info","No cookies set by the server.",""))
            emit(queue,{"type":"log","msg":"[CKI] No cookies found","cls":"info"})
        else:
            for cookie in jar:
                issues = []
                if not cookie.has_nonstandard_attr("HttpOnly") and not cookie.has_nonstandard_attr("httponly"):
                    issues.append("HttpOnly missing")
                if not cookie.secure:
                    issues.append("Secure flag missing")
                name = cookie.name
                if issues:
                    findings.append(make_finding(f"Insecure Cookie: {name}","warning",
                        f"Cookie '{name}' missing flags: {', '.join(issues)}",
                        f"Cookie: {name}; Issues: {', '.join(issues)}"))
                    emit(queue,{"type":"log","msg":f"[CKI] ✗ {name}: {', '.join(issues)}","cls":"warn"})
                else:
                    findings.append(make_finding(f"Secure Cookie: {name}","safe",
                        f"Cookie '{name}' has proper security flags.",""))
                    emit(queue,{"type":"log","msg":f"[CKI] ✓ {name} secure","cls":"ok"})
    except Exception as e:
        emit(queue,{"type":"log","msg":f"[CKI] Error: {e}","cls":"warn"})

    emit(queue,{"type":"progress","pct":32,"label":"Cookies checked","check":"Cookies","state":"done"})
    return findings

# ── OPEN DIRECTORIES ───────────────────────
def check_open_dirs(base_url, queue):
    emit(queue,{"type":"progress","pct":34,"label":"Scanning directories...","check":"Open Dirs","state":"running"})
    findings = []
    found = []
    import urllib.request

    def check_one(path):
        url = base_url.rstrip('/') + '/' + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent":"WebSentry/1.0"})
            resp = urllib.request.urlopen(req, timeout=4)
            code = resp.getcode()
            if code in (200, 403):
                return (path, code)
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return (path, 403)
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(check_one, d): d for d in COMMON_DIRS}
        for f in as_completed(futs):
            res = f.result()
            if res:
                path, code = res
                found.append(res)
                sev = "critical" if code == 200 else "warning"
                findings.append(make_finding(f"Exposed Path: /{path}", sev,
                    f"{'Accessible' if code==200 else 'Exists but forbidden'}: /{path} (HTTP {code})",
                    f"URL: {base_url.rstrip('/')}/{path}"))
                emit(queue,{"type":"log","msg":f"[DIR] HTTP {code}: /{path}","cls":"err" if code==200 else "warn"})

    if not found:
        findings.append(make_finding("No Sensitive Directories Found","safe",
            "Common sensitive directories not publicly accessible.",""))
        emit(queue,{"type":"log","msg":"[DIR] No exposed directories","cls":"ok"})

    emit(queue,{"type":"progress","pct":48,"label":"Directories checked","check":"Open Dirs","state":"done"})
    return findings

# ── PORT SCAN ──────────────────────────────
def check_ports(hostname, queue):
    emit(queue,{"type":"progress","pct":50,"label":"Scanning ports...","check":"Ports","state":"running"})
    findings = []
    open_ports = []

    def scan_port(port):
        try:
            s = socket.socket()
            s.settimeout(1.5)
            r = s.connect_ex((hostname, port))
            s.close()
            return port if r == 0 else None
        except:
            return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(scan_port, p): p for p in COMMON_PORTS}
        for f in as_completed(futs):
            p = f.result()
            if p:
                open_ports.append(p)

    open_ports.sort()
    PORT_NAMES = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
                  80:"HTTP",443:"HTTPS",3306:"MySQL",3389:"RDP",
                  5432:"PostgreSQL",6379:"Redis",8080:"Alt-HTTP",
                  8443:"Alt-HTTPS",8888:"Dev Server",27017:"MongoDB"}
    RISKY = {21,23,3306,5432,6379,27017,3389}

    for p in open_ports:
        svc = PORT_NAMES.get(p, "Unknown")
        sev = "critical" if p in RISKY else "warning" if p in {22,8080,8888} else "info"
        findings.append(make_finding(f"Port {p} Open ({svc})", sev,
            f"Port {p} ({svc}) is publicly accessible.",
            f"Host: {hostname}:{p}"))
        emit(queue,{"type":"log","msg":f"[PORT] Open: {p}/{svc}","cls":"err" if sev=="critical" else "warn"})

    if not open_ports:
        findings.append(make_finding("No Risky Ports Open","safe","No common risky ports found open.",""))
        emit(queue,{"type":"log","msg":"[PORT] All scanned ports closed","cls":"ok"})

    emit(queue,{"type":"progress","pct":62,"label":"Ports scanned","check":"Ports","state":"done"})
    return findings

# ── ROBOTS / SITEMAP ──────────────────────
def check_robots(base_url, queue):
    emit(queue,{"type":"progress","pct":64,"label":"Checking robots.txt...","check":"Robots","state":"running"})
    findings = []
    import urllib.request

    for path in ["robots.txt", "sitemap.xml"]:
        url = base_url.rstrip('/') + '/' + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent":"WebSentry/1.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            content = resp.read(2000).decode('utf-8','ignore')
            emit(queue,{"type":"log","msg":f"[ROB] Found /{path}","cls":"info"})

            if path == "robots.txt":
                disallowed = [l for l in content.split('\n') if l.lower().startswith('disallow:')]
                sensitive = [d for d in disallowed if any(k in d.lower() for k in
                    ['admin','login','password','backup','config','api','secret'])]
                if sensitive:
                    findings.append(make_finding("Sensitive Paths in robots.txt","warning",
                        "robots.txt reveals potentially sensitive paths.",
                        "\n".join(sensitive[:10])))
                    emit(queue,{"type":"log","msg":f"[ROB] Sensitive disallowed paths found","cls":"warn"})
                else:
                    findings.append(make_finding("robots.txt Found","info",
                        f"robots.txt found with {len(disallowed)} Disallow entries.",
                        content[:300]))
            else:
                findings.append(make_finding("sitemap.xml Found","info",
                    "sitemap.xml is publicly accessible.",""))
        except Exception as e:
            findings.append(make_finding(f"{path} Not Found","safe",
                f"/{path} not publicly accessible.",""))
            emit(queue,{"type":"log","msg":f"[ROB] /{path} not found (normal)","cls":"ok"})

    emit(queue,{"type":"progress","pct":70,"label":"Robots checked","check":"Robots","state":"done"})
    return findings

# ── CORS ──────────────────────────────────
def check_cors(url, queue):
    emit(queue,{"type":"progress","pct":72,"label":"Checking CORS policy...","check":"CORS","state":"running"})
    findings = []
    import urllib.request
    try:
        req = urllib.request.Request(url,
            headers={"User-Agent":"WebSentry/1.0","Origin":"https://evil.com"})
        resp = urllib.request.urlopen(req, timeout=6)
        headers = {k.lower():v for k,v in resp.headers.items()}

        acao = headers.get("access-control-allow-origin","")
        acac = headers.get("access-control-allow-credentials","")

        if acao == "*":
            findings.append(make_finding("Wildcard CORS","warning",
                "Access-Control-Allow-Origin: * allows any origin to read responses.",
                f"ACAO: {acao}"))
            emit(queue,{"type":"log","msg":"[CORS] Wildcard ACAO found","cls":"warn"})
        elif "evil.com" in acao:
            findings.append(make_finding("CORS Origin Reflection","critical",
                "Server reflects arbitrary Origin header. Combined with credentials = data theft.",
                f"ACAO: {acao} | ACAC: {acac}"))
            emit(queue,{"type":"log","msg":"[CORS] Origin reflected! Critical","cls":"err"})
        elif acao:
            findings.append(make_finding("CORS Policy Set","safe",
                f"CORS restricted to: {acao}", f"ACAO: {acao}"))
            emit(queue,{"type":"log","msg":f"[CORS] Restricted to {acao}","cls":"ok"})
        else:
            findings.append(make_finding("No CORS Headers","info",
                "No CORS headers found. API may not be accessible cross-origin.",""))
            emit(queue,{"type":"log","msg":"[CORS] No CORS headers","cls":"info"})
    except Exception as e:
        emit(queue,{"type":"log","msg":f"[CORS] Error: {e}","cls":"warn"})

    emit(queue,{"type":"progress","pct":76,"label":"CORS checked","check":"CORS","state":"done"})
    return findings

# ── XSS (Basic Reflection Check) ──────────
def check_xss(url, queue):
    emit(queue,{"type":"progress","pct":78,"label":"Testing XSS vectors...","check":"XSS","state":"running"})
    findings = []
    import urllib.request, urllib.parse

    parsed = urlparse(url)
    # Only test if there are params or use a test param
    test_url = url + ("&" if "?" in url else "?") + "q=" + quote(XSS_PAYLOADS[0])

    try:
        req = urllib.request.Request(test_url, headers={"User-Agent":"WebSentry/1.0"})
        resp = urllib.request.urlopen(req, timeout=6)
        content = resp.read(5000).decode('utf-8','ignore')

        reflected = any(p in content for p in XSS_PAYLOADS)
        if reflected:
            findings.append(make_finding("Potential XSS Reflection","critical",
                "Input appears to be reflected in response without encoding.",
                f"Payload reflected in response. Test URL: {test_url}"))
            emit(queue,{"type":"log","msg":"[XSS] Payload reflected in response!","cls":"err"})
        else:
            findings.append(make_finding("XSS Reflection Test Passed","safe",
                "Test payloads not reflected in response.",""))
            emit(queue,{"type":"log","msg":"[XSS] No reflection detected","cls":"ok"})
    except Exception as e:
        findings.append(make_finding("XSS Check Failed","info",
            "Could not complete XSS reflection test.",str(e)))
        emit(queue,{"type":"log","msg":f"[XSS] Could not test: {e}","cls":"warn"})

    emit(queue,{"type":"progress","pct":82,"label":"XSS checked","check":"XSS","state":"done"})
    return findings

# ── SQL INJECTION (Error Based) ───────────
def check_sqli(url, queue):
    emit(queue,{"type":"progress","pct":83,"label":"Testing SQL injection...","check":"SQLi","state":"running"})
    findings = []
    import urllib.request

    SQL_ERRORS = ["sql syntax","mysql_fetch","ora-","sqlite_","pg_query",
                  "you have an error in your sql","warning: mysql","unclosed quotation"]
    test_url = url + ("&" if "?" in url else "?") + "id=" + quote("'")

    try:
        req = urllib.request.Request(test_url, headers={"User-Agent":"WebSentry/1.0"})
        try:
            resp = urllib.request.urlopen(req, timeout=6)
            content = resp.read(8000).decode('utf-8','ignore').lower()
        except Exception as ex:
            content = str(ex).lower()

        if any(err in content for err in SQL_ERRORS):
            findings.append(make_finding("SQL Injection Detected","critical",
                "SQL error exposed in response — site may be vulnerable to SQL injection.",
                f"Test URL: {test_url}"))
            emit(queue,{"type":"log","msg":"[SQLi] SQL error in response!","cls":"err"})
        else:
            findings.append(make_finding("SQLi Test Passed","safe",
                "No SQL errors detected in response to injection test.",""))
            emit(queue,{"type":"log","msg":"[SQLi] No SQL errors detected","cls":"ok"})
    except Exception as e:
        findings.append(make_finding("SQLi Check Failed","info","Could not test SQL injection.",str(e)))
        emit(queue,{"type":"log","msg":f"[SQLi] Error: {e}","cls":"warn"})

    emit(queue,{"type":"progress","pct":86,"label":"SQLi checked","check":"SQLi","state":"done"})
    return findings

# ── CLICKJACKING ──────────────────────────
def check_clickjacking(url, queue):
    emit(queue,{"type":"progress","pct":87,"label":"Checking clickjacking...","check":"Clickjack","state":"running"})
    findings = []
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"WebSentry/1.0"})
        resp = urllib.request.urlopen(req, timeout=6)
        headers = {k.lower():v for k,v in resp.headers.items()}
        xfo = headers.get("x-frame-options","")
        csp = headers.get("content-security-policy","")

        if xfo.upper() in ("DENY","SAMEORIGIN"):
            findings.append(make_finding("Clickjacking Protected","safe",
                f"X-Frame-Options: {xfo}",f"Header: {xfo}"))
            emit(queue,{"type":"log","msg":f"[CJ] Protected: {xfo}","cls":"ok"})
        elif "frame-ancestors" in csp.lower():
            findings.append(make_finding("Clickjacking Protected via CSP","safe",
                "CSP frame-ancestors directive prevents framing.",""))
            emit(queue,{"type":"log","msg":"[CJ] CSP frame-ancestors found","cls":"ok"})
        else:
            findings.append(make_finding("Clickjacking Vulnerable","warning",
                "No X-Frame-Options or CSP frame-ancestors. Page can be embedded in iframes.",
                "Add: X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'"))
            emit(queue,{"type":"log","msg":"[CJ] No frame protection found","cls":"warn"})
    except Exception as e:
        emit(queue,{"type":"log","msg":f"[CJ] Error: {e}","cls":"warn"})

    emit(queue,{"type":"progress","pct":89,"label":"Clickjacking checked","check":"Clickjack","state":"done"})
    return findings

# ── DNS / INFO LEAK ───────────────────────
def check_dns(hostname, queue):
    emit(queue,{"type":"progress","pct":90,"label":"DNS lookup...","check":"DNS","state":"running"})
    findings = []
    try:
        ip = socket.gethostbyname(hostname)
        findings.append(make_finding("DNS Resolution","info",
            f"Target resolves to IP address.",f"Host: {hostname} → {ip}"))
        emit(queue,{"type":"log","msg":f"[DNS] {hostname} → {ip}","cls":"info"})

        # Check for IP info
        private_ranges = ["10.","172.16.","172.17.","172.18.","172.19.",
                          "172.2","172.3","192.168.","127."]
        if any(ip.startswith(r) for r in private_ranges):
            findings.append(make_finding("Private IP Exposed","warning",
                "Domain resolves to a private IP address.",f"IP: {ip}"))
            emit(queue,{"type":"log","msg":f"[DNS] Private IP: {ip}","cls":"warn"})

    except Exception as e:
        findings.append(make_finding("DNS Resolution Failed","critical",
            "Could not resolve hostname.",str(e)))
        emit(queue,{"type":"log","msg":f"[DNS] Failed: {e}","cls":"err"})

    emit(queue,{"type":"progress","pct":93,"label":"DNS checked","check":"DNS","state":"done"})
    return findings

# ── INFO LEAK ─────────────────────────────
def check_info_leak(base_url, queue):
    emit(queue,{"type":"progress","pct":94,"label":"Checking info leaks...","check":"Info Leak","state":"running"})
    findings = []
    import urllib.request

    leak_paths = [".git/HEAD", ".env", "config.php.bak",
                  "web.config", "phpinfo.php", "info.php", "README.md", "CHANGELOG.md"]

    found_leaks = []
    def check_one(p):
        url = base_url.rstrip('/') + '/' + p
        try:
            req = urllib.request.Request(url, headers={"User-Agent":"WebSentry/1.0"})
            resp = urllib.request.urlopen(req, timeout=4)
            if resp.getcode() == 200:
                snip = resp.read(200).decode('utf-8','ignore')
                return (p, snip)
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(check_one, p): p for p in leak_paths}
        for f in as_completed(futs):
            res = f.result()
            if res:
                path, snip = res
                found_leaks.append(path)
                sev = "critical" if path in [".env","web.config",".git/HEAD"] else "warning"
                findings.append(make_finding(f"Sensitive File Exposed: {path}", sev,
                    f"File '/{path}' is publicly accessible.",
                    f"Preview: {snip[:100]}"))
                emit(queue,{"type":"log","msg":f"[LEAK] Exposed: /{path}","cls":"err"})

    if not found_leaks:
        findings.append(make_finding("No Info Leaks Found","safe",
            "Common sensitive files not publicly accessible.",""))
        emit(queue,{"type":"log","msg":"[LEAK] No sensitive files exposed","cls":"ok"})

    emit(queue,{"type":"progress","pct":97,"label":"Info leaks checked","check":"Info Leak","state":"done"})
    return findings

# ── REDIRECTS ─────────────────────────────
def check_redirects(url, queue):
    emit(queue,{"type":"progress","pct":97,"label":"Checking redirects...","check":"Redirects","state":"running"})
    findings = []
    import urllib.request
    try:
        test_url = url.rstrip('/') + "/?redirect=https://evil.com"
        req = urllib.request.Request(test_url,
            headers={"User-Agent":"WebSentry/1.0"})
        resp = urllib.request.urlopen(req, timeout=6)
        final_url = resp.geturl()
        if "evil.com" in final_url:
            findings.append(make_finding("Open Redirect","critical",
                "Site follows redirect to external URL without validation.",
                f"Redirected to: {final_url}"))
            emit(queue,{"type":"log","msg":"[REDIR] Open redirect confirmed!","cls":"err"})
        else:
            findings.append(make_finding("Open Redirect Test Passed","safe",
                "No open redirect detected in basic test.",""))
            emit(queue,{"type":"log","msg":"[REDIR] No open redirect","cls":"ok"})
    except Exception as e:
        findings.append(make_finding("Redirect Check","info",
            "Could not complete redirect test.",str(e)))
        emit(queue,{"type":"log","msg":f"[REDIR] Could not test: {e}","cls":"warn"})

    emit(queue,{"type":"progress","pct":98,"label":"Redirects checked","check":"Redirects","state":"done"})
    return findings

# ── FORMS / CSRF ───────────────────────────
def check_forms_csrf(url, queue):
    emit(queue,{"type":"progress","pct":98,"label":"Checking forms...","check":"CSRF","state":"running"})
    emit(queue,{"type":"progress","pct":98,"label":"Checking forms...","check":"Forms","state":"running"})
    findings = []
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"WebSentry/1.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        content = resp.read(30000).decode('utf-8','ignore')

        forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL|re.IGNORECASE)
        if not forms:
            findings.append(make_finding("No Forms Found","info","No HTML forms detected on main page.",""))
            emit(queue,{"type":"log","msg":"[FORM] No forms found","cls":"info"})
        else:
            for i, form in enumerate(forms[:5]):
                has_csrf = bool(re.search(
                    r'(csrf|_token|authenticity_token|nonce)', form, re.IGNORECASE))
                if has_csrf:
                    findings.append(make_finding(f"Form #{i+1}: CSRF Token Present","safe",
                        "CSRF protection token found in form.",""))
                    emit(queue,{"type":"log","msg":f"[FORM] Form {i+1}: CSRF token OK","cls":"ok"})
                else:
                    action = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
                    act = action.group(1) if action else "unknown"
                    findings.append(make_finding(f"Form #{i+1}: No CSRF Token","warning",
                        f"Form (action={act}) lacks CSRF token. Vulnerable to cross-site request forgery.",
                        f"Form action: {act}"))
                    emit(queue,{"type":"log","msg":f"[FORM] Form {i+1}: No CSRF token","cls":"warn"})
    except Exception as e:
        emit(queue,{"type":"log","msg":f"[FORM] Error: {e}","cls":"warn"})

    emit(queue,{"type":"progress","pct":99,"label":"Forms checked","check":"CSRF","state":"done"})
    emit(queue,{"type":"progress","pct":99,"label":"Forms checked","check":"Forms","state":"done"})
    return findings


# ─────────────────────────────────────────────
# FLASK ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    raw_url = data.get('url','').strip()

    if not raw_url.startswith(('http://','https://')):
        raw_url = 'https://' + raw_url

    parsed = urlparse(raw_url)
    hostname = parsed.hostname
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    def generate():
        queue = []

        def eq(evt): queue.append(json.dumps(evt) + "\n")

        eq({"type":"log","msg":f"Starting scan of {raw_url}","cls":"info"})
        start = time.time()

        all_findings = []

        # Run checks
        all_findings += check_ssl(parsed, queue)
        yield from queue; queue.clear()

        all_findings += check_headers(raw_url, {}, queue)
        yield from queue; queue.clear()

        all_findings += check_cookies(raw_url, queue)
        yield from queue; queue.clear()

        all_findings += check_open_dirs(base_url, queue)
        yield from queue; queue.clear()

        all_findings += check_ports(hostname, queue)
        yield from queue; queue.clear()

        all_findings += check_robots(base_url, queue)
        yield from queue; queue.clear()

        all_findings += check_cors(raw_url, queue)
        yield from queue; queue.clear()

        all_findings += check_xss(raw_url, queue)
        yield from queue; queue.clear()

        all_findings += check_sqli(raw_url, queue)
        yield from queue; queue.clear()

        all_findings += check_clickjacking(raw_url, queue)
        yield from queue; queue.clear()

        all_findings += check_dns(hostname, queue)
        yield from queue; queue.clear()

        all_findings += check_info_leak(base_url, queue)
        yield from queue; queue.clear()

        all_findings += check_redirects(raw_url, queue)
        yield from queue; queue.clear()

        all_findings += check_forms_csrf(raw_url, queue)
        yield from queue; queue.clear()

        duration = round(time.time() - start, 1)
        eq({"type":"progress","pct":100,"label":f"Complete in {duration}s"})
        eq({"type":"done","data":{
            "url": raw_url,
            "duration": duration,
            "findings": all_findings
        }})
        yield from queue

    return Response(generate(), mimetype='text/plain',
                    headers={"X-Accel-Buffering":"no",
                             "Cache-Control":"no-cache"})


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════╗
║          WebSentry Vulnerability         ║
║               Scanner v1.0              ║
╠══════════════════════════════════════════╣
║  Open: http://localhost:5000             ║
║  Press Ctrl+C to stop                   ║
╚══════════════════════════════════════════╝
""")
    # app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

port = int(os.environ.get("PORT", 5000))
app.run(host='0.0.0.0', port=port)
