/* ═══════════════════════════════════════════════════════════════════════
   StealthVault — site.js
   Loads config.json (same origin) and uses it to drive:
     • app name / version / footer text / menu links
     • default settings for users who haven't changed them
     • announcements (pop-up or banner), scheduled, dismissible, live-updating
   Nothing here is trusted as HTML: all text is rendered with textContent and
   links must be http(s) or same-site relative paths.
   Set window.SV_NO_AUTOSTART = true before loading to use only the API (admin page).
═══════════════════════════════════════════════════════════════════════ */
(() => {
'use strict';

const CONFIG_URL  = 'config.json';
const DISMISS_KEY = 'sv-dismissed-announcements';
const POLL_MS     = 5 * 60 * 1000;   // new announcements appear within 5 min, no reload needed
const TYPES = {
  info:     { icon: 'ℹ️', color: 'var(--accent)',  rank: 3, label: 'Info' },
  success:  { icon: '✅', color: 'var(--success)', rank: 2, label: 'Success' },
  warning:  { icon: '⚠️', color: 'var(--warn)',    rank: 1, label: 'Warning' },
  critical: { icon: '🚨', color: 'var(--error)',   rank: 0, label: 'Critical' },
};

// ── helpers ──────────────────────────────────────────────────────────
const str = (v, max = 500) => (typeof v === 'string' ? v : v == null ? '' : String(v)).slice(0, max);
function safeUrl(u) {
  u = str(u, 1000).trim(); if (!u) return '';
  try { const x = new URL(u, location.href); return (x.protocol === 'http:' || x.protocol === 'https:') ? x.href : ''; }
  catch { return ''; }
}
const toTime = v => { if (!v) return null; const t = Date.parse(v); return Number.isFinite(t) ? t : null; };

// Coerce anything into a well-formed config (never throws)
function normalize(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  const a = r.app && typeof r.app === 'object' ? r.app : {};
  const domains = {};
  if (a.domains && typeof a.domains === 'object') for (const [k, v] of Object.entries(a.domains)) if (k && v) domains[str(k, 40)] = str(v, 200);
  return {
    app: {
      name: str(a.name, 60) || 'StealthVault',
      logoMain: str(a.logoMain, 30) || 'STEALTH',
      logoAccent: str(a.logoAccent, 30) || 'VAULT',
      version: str(a.version, 30), repo: str(a.repo, 100), domains,
    },
    defaults: r.defaults && typeof r.defaults === 'object' ? r.defaults : {},
    links: (Array.isArray(r.links) ? r.links : []).slice(0, 12).map(l => ({
      icon: str(l && l.icon, 4) || '🔗', label: str(l && l.label, 60), url: str(l && l.url, 1000),
    })).filter(l => l.label && l.url),
    announcements: (Array.isArray(r.announcements) ? r.announcements : []).slice(0, 50).map((x, i) => {
      x = x && typeof x === 'object' ? x : {};
      return {
        id: str(x.id, 60) || 'a-' + i, enabled: x.enabled !== false,
        type: TYPES[x.type] ? x.type : 'info', style: x.style === 'banner' ? 'banner' : 'popup',
        title: str(x.title, 120), message: str(x.message, 1200),
        linkText: str(x.linkText, 60), linkUrl: str(x.linkUrl, 1000),
        startsAt: str(x.startsAt, 40), endsAt: str(x.endsAt, 40),
        dismissible: x.dismissible !== false,
      };
    }),
  };
}

// 'live' | 'scheduled' | 'expired' | 'disabled'
function statusOf(a, now = Date.now()) {
  if (!a.enabled) return 'disabled';
  const s = toTime(a.startsAt), e = toTime(a.endsAt);
  if (s !== null && now < s) return 'scheduled';
  if (e !== null && now > e) return 'expired';
  return 'live';
}

function getDismissed() { try { const d = JSON.parse(localStorage.getItem(DISMISS_KEY) || '[]'); return Array.isArray(d) ? d : []; } catch { return []; } }
function addDismissed(id) { try { const d = getDismissed(); if (!d.includes(id)) d.push(id); localStorage.setItem(DISMISS_KEY, JSON.stringify(d.slice(-200))); } catch {} }
function clearDismissed() { try { localStorage.removeItem(DISMISS_KEY); } catch {} }

// ── styles (injected so no CSS file needs editing) ──────────────────────
function injectStyles() {
  if (document.getElementById('sv-site-css')) return;
  const st = document.createElement('style'); st.id = 'sv-site-css';
  st.textContent = `
  .sv-overlay{position:fixed;inset:0;z-index:400;background:rgba(4,8,16,.72);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;padding:20px;animation:sv-fade .18s ease}
  .sv-modal{width:min(460px,100%);max-height:90vh;overflow:auto;background:var(--surface,#0d1017);border:1px solid var(--border2,#263349);border-top:3px solid var(--sv-c,var(--accent));border-radius:14px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.6);color:var(--text,#e8eaf0);font-family:var(--font,system-ui);animation:sv-pop .22s ease}
  .sv-modal h3{font-size:17px;margin:0 0 8px;display:flex;gap:10px;align-items:center}
  .sv-modal p{font-size:14px;line-height:1.65;color:var(--text2,#8892a4);white-space:pre-wrap;word-break:break-word;margin:0}
  .sv-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:20px;flex-wrap:wrap}
  .sv-btn{padding:9px 18px;border-radius:9px;border:1px solid var(--border2,#263349);background:var(--surface2,#111520);color:var(--text,#e8eaf0);font:600 13px var(--font,system-ui);cursor:pointer;text-decoration:none;display:inline-block}
  .sv-btn:hover{border-color:var(--accent)}
  .sv-btn.primary{background:var(--sv-c,var(--accent));border-color:transparent;color:#04101a}
  .sv-banners{position:relative;z-index:120}
  .sv-banner{display:flex;gap:12px;align-items:center;padding:10px 18px;font:500 13px var(--font,system-ui);background:var(--surface2,#111520);border-bottom:1px solid var(--sv-c,var(--accent));color:var(--text,#e8eaf0)}
  .sv-banner .sv-bt{flex:1;min-width:0;word-break:break-word}.sv-banner b{margin-right:6px}
  .sv-banner a{color:var(--sv-c,var(--accent));font-weight:700}
  .sv-banner button{background:none;border:none;color:var(--text2,#8892a4);font-size:16px;cursor:pointer}
  .sv-menu-item{display:flex;align-items:center;gap:12px;padding:12px;margin-bottom:8px;border-radius:8px;border:none;width:100%;text-align:left;text-decoration:none;color:var(--text,#e8eaf0);background:var(--surface2,#111520);cursor:pointer;font:600 14px var(--font,system-ui)}
  .sv-menu-item:hover{background:var(--surface3,#172540)}
  .sv-list-item{border-left:3px solid var(--sv-c,var(--accent));padding:8px 12px;margin-top:12px;background:var(--surface2,#111520);border-radius:0 8px 8px 0}
  .sv-list-item b{font-size:13px}.sv-list-item p{font-size:12.5px;margin-top:4px}
  @keyframes sv-fade{from{opacity:0}to{opacity:1}}@keyframes sv-pop{from{opacity:0;transform:translateY(10px) scale(.97)}to{opacity:1;transform:none}}`;
  document.head.appendChild(st);
}

const el = (tag, props = {}, kids = []) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) k === 'text' ? (n.textContent = v) : k === 'class' ? (n.className = v) : n.setAttribute(k, v);
  kids.forEach(c => c && n.appendChild(c)); return n;
};

// ── popup ───────────────────────────────────────────────────────────
// opts.preview = true → never records dismissal. Returns a promise that resolves when closed.
function showPopup(a, opts = {}) {
  injectStyles();
  const t = TYPES[a.type] || TYPES.info;
  return new Promise(resolve => {
    const prevFocus = document.activeElement;
    const close = () => { document.removeEventListener('keydown', onKey, true); ov.remove(); if (prevFocus && prevFocus.focus) try { prevFocus.focus(); } catch {} resolve(); };
    const dismiss = () => { if (!opts.preview) addDismissed(a.id); close(); };
    const onKey = e => { if (e.key === 'Escape') { e.stopPropagation(); dismiss(); } };
    const url = safeUrl(a.linkUrl);
    const ok = el('button', { class: 'sv-btn' + (url ? '' : ' primary'), text: url ? 'Dismiss' : 'Got it' });
    ok.addEventListener('click', dismiss);
    const actions = el('div', { class: 'sv-actions' }, [ok]);
    if (url) {
      const go = el('a', { class: 'sv-btn primary', href: url, target: '_blank', rel: 'noopener noreferrer', text: a.linkText || 'Learn more' });
      go.addEventListener('click', () => { if (!opts.preview) addDismissed(a.id); });
      actions.appendChild(go);
    }
    const modal = el('div', { class: 'sv-modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': a.title || t.label }, [
      el('h3', {}, [el('span', { text: t.icon }), el('span', { text: a.title || t.label })]),
      el('p', { text: a.message }), actions,
    ]);
    modal.style.setProperty('--sv-c', t.color);
    const ov = el('div', { class: 'sv-overlay' }, [modal]);
    ov.addEventListener('mousedown', e => { if (e.target === ov) dismiss(); });
    document.addEventListener('keydown', onKey, true);
    document.body.appendChild(ov); ok.focus();
  });
}

// ── banners ─────────────────────────────────────────────────────────
function renderBanners(list) {
  injectStyles();
  let box = document.getElementById('sv-banners');
  if (!box) { box = el('div', { id: 'sv-banners', class: 'sv-banners' }); document.body.prepend(box); }
  box.textContent = '';
  const dismissed = getDismissed();
  list.forEach(a => {
    if (a.dismissible && dismissed.includes(a.id)) return;
    const t = TYPES[a.type];
    const txt = el('div', { class: 'sv-bt' }, [el('b', { text: t.icon + ' ' + a.title }), el('span', { text: a.message })]);
    const url = safeUrl(a.linkUrl);
    if (url) { txt.appendChild(document.createTextNode(' ')); txt.appendChild(el('a', { href: url, target: '_blank', rel: 'noopener noreferrer', text: a.linkText || 'Learn more' })); }
    const row = el('div', { class: 'sv-banner', role: 'status' }, [txt]);
    row.style.setProperty('--sv-c', t.color);
    if (a.dismissible) {
      const x = el('button', { 'aria-label': 'Dismiss', text: '✕' });
      x.addEventListener('click', () => { addDismissed(a.id); row.remove(); });
      row.appendChild(x);
    }
    box.appendChild(row);
  });
}

// ── announcement list modal (replaces a static changelog) ───────────────
function showAnnouncementList(cfg) {
  injectStyles();
  const live = cfg.announcements.filter(a => statusOf(a) === 'live').sort((a, b) => TYPES[a.type].rank - TYPES[b.type].rank);
  const body = el('div');
  if (!live.length) body.appendChild(el('p', { text: 'No announcements right now.' }));
  live.forEach(a => {
    const t = TYPES[a.type];
    const row = el('div', { class: 'sv-list-item' }, [el('b', { text: t.icon + ' ' + a.title }), el('p', { text: a.message })]);
    row.style.setProperty('--sv-c', t.color); body.appendChild(row);
  });
  const ov = el('div', { class: 'sv-overlay' });
  const close = () => { document.removeEventListener('keydown', onKey, true); ov.remove(); };
  const onKey = e => { if (e.key === 'Escape') { e.stopPropagation(); close(); } };
  const ok = el('button', { class: 'sv-btn primary', text: 'Close' }); ok.addEventListener('click', close);
  ov.appendChild(el('div', { class: 'sv-modal', role: 'dialog', 'aria-modal': 'true' }, [el('h3', { text: '📣 Announcements' }), body, el('div', { class: 'sv-actions' }, [ok])]));
  ov.addEventListener('mousedown', e => { if (e.target === ov) close(); });
  document.addEventListener('keydown', onKey, true); document.body.appendChild(ov); ok.focus();
}

// ── apply config to the page ────────────────────────────────────────
let current = null, lastSig = '', popupBusy = false;

function applyChrome(cfg) {
  const a = cfg.app;
  document.title = a.name;
  const logo = document.querySelector('nav .logo');
  if (logo) { logo.textContent = '■ ' + a.logoMain; logo.appendChild(el('span', { text: a.logoAccent })); }
  const about = document.getElementById('about-note');
  if (about) { about.textContent = `${a.name}${a.version ? ' ' + a.version : ''} · AES-256-GCM · PBKDF2 310k rounds`; about.appendChild(document.createElement('br')); about.appendChild(document.createTextNode('Settings saved in your browser (localStorage).')); }

  const box = document.getElementById('menu-links');
  if (box) {
    box.textContent = '';
    const ann = el('button', { class: 'sv-menu-item', type: 'button' }, [el('span', { text: '📣', style: 'font-size:18px' }), el('span', { text: 'Announcements' })]);
    ann.addEventListener('click', () => { document.getElementById('btn-close-menu')?.click(); showAnnouncementList(current || cfg); });
    box.appendChild(ann);
    cfg.links.forEach(l => {
      const url = safeUrl(l.url); if (!url) return;
      box.appendChild(el('a', { class: 'sv-menu-item', href: url, target: '_blank', rel: 'noopener noreferrer' }, [el('span', { text: l.icon, style: 'font-size:18px' }), el('span', { text: l.label })]));
    });
  }
  if (window.SV && window.SV.applyRemoteDefaults) window.SV.applyRemoteDefaults(cfg.defaults);
}

function viewerOpen() { const v = document.getElementById('viewer-modal'); return !!v && !v.classList.contains('hidden'); }

async function presentAnnouncements(cfg) {
  const live = cfg.announcements.filter(a => statusOf(a) === 'live');
  renderBanners(live.filter(a => a.style === 'banner'));
  if (popupBusy) return;
  const dismissed = getDismissed();
  const queue = live.filter(a => a.style === 'popup' && !dismissed.includes(a.id)).sort((a, b) => TYPES[a.type].rank - TYPES[b.type].rank);
  if (!queue.length) return;
  popupBusy = true;
  try {
    for (const a of queue) {
      while (viewerOpen()) await new Promise(r => setTimeout(r, 5000));   // never interrupt media viewing
      if (getDismissed().includes(a.id)) continue;
      await showPopup(a);
    }
  } finally { popupBusy = false; }
}

async function fetchConfig() {
  try {
    const res = await fetch(CONFIG_URL + '?t=' + Date.now(), { cache: 'no-store' });
    if (!res.ok) return null;
    return normalize(await res.json());
  } catch { return null; }
}

async function refresh() {
  const cfg = await fetchConfig(); if (!cfg) return;
  const sig = JSON.stringify(cfg);
  if (sig === lastSig) { presentAnnouncements(cfg); return; }   // unchanged → only re-check schedules
  lastSig = sig; current = cfg;
  applyChrome(cfg); presentAnnouncements(cfg);
}

function start() {
  injectStyles(); refresh();
  setInterval(refresh, POLL_MS);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
}

window.SVSite = { normalize, statusOf, safeUrl, showPopup, renderBanners, fetchConfig, clearDismissed, getDismissed, TYPES, refresh };
if (!window.SV_NO_AUTOSTART) {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
}
})();
