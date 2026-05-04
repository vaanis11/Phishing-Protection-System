/* PhishGuard — Frontend Application
   Matches index.html v2 element IDs exactly */

// ── Demo URLs ──────────────────────────────────────────────────────────────
const DEMOS = [
  'http://paypa1.com.secure-verify.xyz/login/confirm?token=abc123&redirect=http://evil.tk',
  'http://amazon-account-suspended.click/verify/billing/update?urgent=true',
  'http://192.168.1.105/banking/login?session=expired&verify=now',
  'http://g00gle-security-alert.top/signin/verify/account/now',
  'https://microsoft-helpdesk-support.xyz/password/reset/immediate',
];
let demoIdx = 0;

function setDemo(i) {
  document.getElementById('urlInput').value = DEMOS[i] || DEMOS[0];
}
function loadDemo() {
  document.getElementById('urlInput').value = DEMOS[demoIdx % DEMOS.length];
  demoIdx++;
}
function clearAll() {
  document.getElementById('urlInput').value = '';
  document.getElementById('errorBox').classList.add('hidden');
  document.getElementById('results').classList.add('hidden');
}

// ── Clock ──────────────────────────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById('navClock');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toUTCString().slice(17, 25) + ' UTC';
}
updateClock();
setInterval(updateClock, 1000);

// ── Boot Sequence ──────────────────────────────────────────────────────────
const BOOT_LINES = [
  'INITIALIZING PHISHGUARD ENGINE v2.0...',
  'LOADING THREAT INTELLIGENCE DATABASE...',
  'CALIBRATING ENTROPY ANALYZER...',
  'CONNECTING TO DOMAIN INTEL MODULE...',
  'ARMING DETECTION SYSTEMS...',
  'ALL SYSTEMS OPERATIONAL.',
];

(function bootSequence() {
  const textEl = document.getElementById('bootText');
  const barEl  = document.getElementById('bootBar');
  const screen = document.getElementById('bootScreen');
  if (!textEl || !screen) return;

  let lineIdx = 0;
  function nextLine() {
    if (lineIdx >= BOOT_LINES.length) {
      setTimeout(() => {
        screen.classList.add('fade-out');
        setTimeout(() => screen.remove(), 600);
      }, 300);
      return;
    }
    textEl.textContent = '> ' + BOOT_LINES[lineIdx];
    const pct = Math.round(((lineIdx + 1) / BOOT_LINES.length) * 100);
    if (barEl) barEl.style.width = pct + '%';
    lineIdx++;
    setTimeout(nextLine, 260);
  }
  setTimeout(nextLine, 200);
})();

// ── Main Scan ──────────────────────────────────────────────────────────────
async function runScan() {
  const url    = (document.getElementById('urlInput').value || '').trim();
  const btn    = document.getElementById('scanBtn');
  const errBox = document.getElementById('errorBox');
  const results = document.getElementById('results');

  errBox.classList.add('hidden');
  results.classList.add('hidden');

  if (!url) { showError('No URL provided. Paste a target URL in the terminal above.'); return; }

  btn.disabled = true;
  btn.innerHTML = '<span>◌</span> SCANNING...';

  try {
    const res  = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();

    if (data.error) { showError(data.error); return; }

    renderResults(data);
    loadStats();
  } catch (e) {
    showError('Engine connection failed. Is the Flask server running?');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>◈</span> EXECUTE SCAN';
  }
}

function showError(msg) {
  document.getElementById('errMsg').textContent = msg;
  document.getElementById('errorBox').classList.remove('hidden');
}

// ── Render Results ─────────────────────────────────────────────────────────
function renderResults(data) {
  const score   = data.risk_score   ?? 0;
  const verdict = data.verdict      ?? 'SAFE';
  const conf    = data.confidence   ?? 0;

  /* ── Scan ID ── */
  const idEl = document.getElementById('scanId');
  if (idEl) idEl.textContent = 'ID: ' + (data.url_id || '—');

  /* ── Verdict panel class ── */
  const vPanel = document.getElementById('verdictPanel');
  if (vPanel) {
    vPanel.className = 'panel panel-verdict verd-' + verdict;
  }

  /* ── Verdict icon & word ── */
  const iconMap = { PHISHING:'⬡', SUSPICIOUS:'◈', CAUTION:'◑', SAFE:'◉' };
  const iconEl  = document.getElementById('verdictIcon');
  const wordEl  = document.getElementById('verdictWord');
  const lblEl   = document.getElementById('verdictLabel');
  if (iconEl) iconEl.textContent = iconMap[verdict] || '◈';
  if (wordEl) wordEl.textContent = verdict;
  if (lblEl)  lblEl.textContent  = data.verdict_label || '';

  /* ── Score number ── */
  const scoreNumEl = document.getElementById('scoreNum');
  if (scoreNumEl) {
    let n = 0;
    const target = score;
    const step = () => {
      n = Math.min(n + 3, target);
      scoreNumEl.textContent = n;
      if (n < target) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  /* ── Score bar ── */
  const fillEl = document.getElementById('scoreFill');
  if (fillEl) {
    fillEl.style.width = '0%';
    setTimeout(() => { fillEl.style.width = score + '%'; }, 60);
    fillEl.className = 'rsb-fill ' + (
      score >= 70 ? 'fill-critical' :
      score >= 45 ? 'fill-high'     :
      score >= 20 ? 'fill-medium'   : 'fill-safe'
    );
  }

  /* ── Confidence bar ── */
  const confFill = document.getElementById('confFill');
  const confNum  = document.getElementById('confNum');
  if (confFill) { confFill.style.width = '0%'; setTimeout(() => { confFill.style.width = conf + '%'; }, 80); }
  if (confNum)  confNum.textContent = conf + '%';

  /* ── Domain rows ── */
  const di       = data.domain_info || {};
  const domRowsEl = document.getElementById('domRows');
  if (domRowsEl) {
    const fields = [
      ['APEX DOMAIN',  di.apex      || '—'],
      ['SUBDOMAIN',    di.subdomain || '(none)'],
      ['TLD',          di.tld       || '—'],
      ['SCHEME',       (di.scheme   || '—').toUpperCase()],
      ['ENTROPY',      di.entropy   !== undefined ? di.entropy : '—'],
      ['WHITELISTED',  data.whitelisted ? '✓ YES' : '✗ NO'],
    ];
    domRowsEl.innerHTML = fields.map(([k, v]) => `
      <div class="dom-row">
        <span class="dom-key">${k}</span>
        <span class="dom-val">${v}</span>
      </div>`).join('');
  }

  /* ── Threat matrix tags & bars ── */
  const tagsEl = document.getElementById('matrixTags');
  const barsEl = document.getElementById('matrixBars');
  const findings = data.findings || [];

  if (tagsEl) {
    if (findings.length === 0) {
      tagsEl.innerHTML = '<div class="mtag mtag-SAFE">NO THREATS DETECTED</div>';
    } else {
      const catSev = {};
      const sevOrd = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1 };
      findings.forEach(f => {
        if (!catSev[f.category] || sevOrd[f.severity] > sevOrd[catSev[f.category]])
          catSev[f.category] = f.severity;
      });
      tagsEl.innerHTML = Object.entries(catSev)
        .map(([cat, sev]) => `<div class="mtag mtag-${sev}">${cat}</div>`)
        .join('');
    }
  }

  if (barsEl) {
    const sevColors = { CRITICAL: 'var(--danger)', HIGH: 'var(--warn)', MEDIUM: '#ff8c00', LOW: 'var(--text-mid)' };
    const sevWidths  = { CRITICAL: 95, HIGH: 70, MEDIUM: 45, LOW: 20 };
    const catSev2 = {};
    const sevOrd2  = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1 };
    findings.forEach(f => {
      if (!catSev2[f.category] || sevOrd2[f.severity] > sevOrd2[catSev2[f.category]])
        catSev2[f.category] = f.severity;
    });
    barsEl.innerHTML = Object.entries(catSev2).slice(0, 6).map(([cat, sev]) => `
      <div class="mbar-row">
        <span class="mbar-label">${cat}</span>
        <div class="mbar-track">
          <div class="mbar-fill" style="width:0%;background:${sevColors[sev]}" data-w="${sevWidths[sev]}"></div>
        </div>
      </div>`).join('');

    // Animate bars
    setTimeout(() => {
      barsEl.querySelectorAll('.mbar-fill').forEach(b => {
        b.style.width = b.dataset.w + '%';
      });
    }, 100);
  }

  /* ── Findings list ── */
  const findListEl  = document.getElementById('findingsList');
  const findCountEl = document.getElementById('findCount');

  if (findCountEl) findCountEl.textContent = findings.length + ' signal' + (findings.length !== 1 ? 's' : '');

  if (findListEl) {
    if (findings.length === 0) {
      findListEl.innerHTML = '<div class="no-findings">◉ No threat indicators detected — URL appears clean</div>';
    } else {
      const order = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3 };
      const sorted = [...findings].sort((a, b) => (order[a.severity]??9) - (order[b.severity]??9));
      findListEl.innerHTML = sorted.map((f, i) => `
        <div class="finding finding-${f.severity}" style="animation-delay:${i*0.05}s">
          <span class="find-sev sev-${f.severity}">${f.severity}</span>
          <div class="find-meta">
            <span class="find-cat">${f.category}</span>
            <span class="find-detail">${f.detail}</span>
          </div>
        </div>`).join('');
    }
  }

  /* ── Scan meta footer ── */
  const metaEl = document.getElementById('scanMeta');
  if (metaEl) {
    const shortUrl = data.url.length > 90 ? data.url.slice(0, 90) + '…' : data.url;
    metaEl.textContent = `SCAN ID: ${data.url_id || '—'}  ·  ${data.timestamp || ''}  ·  ${shortUrl}`;
  }

  /* ── Show results ── */
  const resultsEl = document.getElementById('results');
  resultsEl.classList.remove('hidden');
  resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });

  /* ── Update threat count in nav ── */
  updateThreatCount(verdict);
}

// ── Threat counter in nav ──────────────────────────────────────────────────
let sessionThreats = 0;
function updateThreatCount(verdict) {
  if (verdict === 'PHISHING' || verdict === 'SUSPICIOUS') sessionThreats++;
  const el = document.getElementById('threatCount');
  if (el) el.textContent = sessionThreats + ' THREAT' + (sessionThreats !== 1 ? 'S' : '');
}

// ── Load Stats ─────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res  = await fetch('/api/stats');
    const data = await res.json();

    const set = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val ?? 0; };
    set('hs-total',   data.total_scans     ?? 0);
    set('hs-threats', data.threats_detected ?? 0);
    set('hs-sus',     data.suspicious       ?? 0);
    set('hs-safe',    data.safe_urls        ?? 0);

    /* ── Feed rows ── */
    const feedEl = document.getElementById('feedRows');
    if (feedEl) {
      const recent = data.recent || [];
      if (recent.length === 0) {
        feedEl.innerHTML = '<div class="feed-empty mono">Awaiting scan data...</div>';
      } else {
        feedEl.innerHTML = recent.map(r => `
          <div class="feed-row">
            <span><span class="feed-verdict fv-${r.verdict}">${r.verdict}</span></span>
            <span class="feed-url mono">${r.url}</span>
            <span class="feed-score mono">${r.risk_score}/100</span>
            <span class="feed-time mono">${(r.timestamp || '').slice(0, 19)}</span>
          </div>`).join('');
      }
    }
  } catch (e) {
    // Non-critical — fail silently
  }
}

// ── Keyboard shortcut ──────────────────────────────────────────────────────
document.getElementById('urlInput')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') runScan();
});

// ── Init ───────────────────────────────────────────────────────────────────
loadStats();
setInterval(loadStats, 30000);