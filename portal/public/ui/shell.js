/* TrendAI Demo Platform — shell runtime shared by every portal page.
 *
 * <body data-page="home|activity|connections|system|tool"> with
 *   <div class="shell"><aside class="side" id="side"></aside><main class="main">…</main></div>
 * Load /demos.js first. Exposes window.TA helpers. The side menu is the only
 * navigation: tools come from window.TRENDAI_DEMOS, a tool's sections are its
 * sub-items when it is open.
 */
(function () {
  const ICONS = {
    home: '<path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V21h14V9.5"/>',
    activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="m9 15 2 2 4-4"/>',
    server: '<rect x="2" y="3" width="20" height="7" rx="1.5"/><rect x="2" y="14" width="20" height="7" rx="1.5"/><path d="M6 6.5h.01M6 17.5h.01"/>',
    scan: '<path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="12" cy="12" r="3"/>',
    chat: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
    calc: '<rect x="4" y="2" width="16" height="20" rx="2"/><path d="M8 6h8M8 10h.01M12 10h.01M16 10h.01M8 14h.01M12 14h.01M16 14v4M8 18h4"/>',
    phone: '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>',
    plug: '<path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0z"/><path d="M12 18v4"/>',
    layers: '<path d="m12 2 10 5-10 5L2 7z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
    external: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
    ai: '<rect x="4" y="8" width="16" height="12" rx="2"/><path d="M12 8V4M8 4h8M9 14h.01M15 14h.01"/>',
  };
  const icon = (name, size = 16) =>
    `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ICONS.shield}</svg>`;
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  async function api(path, opts = {}) {
    const init = { ...opts, headers: { ...(opts.body ? { 'Content-Type': 'application/json' } : {}), ...(opts.headers || {}) } };
    if (init.body && typeof init.body !== 'string') init.body = JSON.stringify(init.body);
    const r = await fetch(path, init);
    if (r.status === 401) { location.href = '/login'; throw new Error('Not signed in'); }
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || d.detail || `HTTP ${r.status}`);
    return d;
  }

  let toastTimer;
  function toast(text) {
    let t = document.getElementById('ta-toast');
    if (!t) { t = document.createElement('div'); t.id = 'ta-toast'; t.className = 'toast'; t.setAttribute('role', 'status'); document.body.appendChild(t); }
    t.textContent = text; t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 2600);
  }

  const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  const demos = () => window.TRENDAI_DEMOS || [];
  const demoById = (id) => demos().find((d) => d.id === id);
  const toolIdFromPath = () => (location.pathname.match(/^\/tool\/([^/]+)/) || [])[1] || '';

  const CATEGORIES = ['Demo Tools', 'Business Tools', 'Other'];

  function navItem(href, ico, label, active, extra = '') {
    return `<a class="nav-item${active ? ' active' : ''}" href="${href}" data-label="${esc(label.toLowerCase())}"${active ? ' aria-current="page"' : ''}>${icon(ico)}<span class="grow">${esc(label)}</span>${extra}</a>`;
  }

  function renderSide(session) {
    const side = document.getElementById('side');
    if (!side) return;
    const page = document.body.dataset.page;
    const toolId = toolIdFromPath();
    const host = session.hostLabel || location.host;
    const groups = CATEGORIES.map((cat) => {
      const items = demos().filter((d) => (d.category || 'Other') === cat).map((d) => {
        const active = page === 'tool' && toolId === d.id;
        let html = navItem(`/tool/${d.id}`, d.icon, d.short || d.title, active);
        if (active && d.sections && d.sections.length) {
          const sec = (location.hash || '#' + d.sections[0].id).slice(1);
          html += `<div class="nav-sub">${d.sections.map((s) => `<a href="/tool/${d.id}#${s.id}" class="${s.id === sec ? 'active' : ''}" data-label="${esc(s.label.toLowerCase())}">${esc(s.label)}</a>`).join('')}</div>`;
        }
        return html;
      }).join('');
      return items ? `<div class="nav-group"><span class="nav-label">${esc(cat)}</span>${items}</div>` : '';
    }).join('');
    const exp = session.expiresAt ? Math.max(0, Math.round((session.expiresAt - Date.now()) / 3600000)) : null;
    side.innerHTML = `
      <a class="brand" href="/"><span class="brand-mark">AI</span><span style="min-width:0"><span class="brand-name">TrendAI <span>Demo Platform</span></span><span class="brand-host">${esc(host)}</span></span></a>
      <label class="side-search">${icon('search')}<input type="search" id="navSearch" aria-label="Search tools and settings" placeholder="Search"><span class="kbd">⌘K</span></label>
      <div class="nav-group"><span class="nav-label">Workspace</span>
        ${navItem('/', 'home', 'Home', page === 'home')}
        ${navItem('/activity', 'activity', 'Activity', page === 'activity', '<span class="nav-count" id="navBlocked" hidden></span>')}
      </div>
      ${groups}
      <div class="nav-group"><span class="nav-label">Platform</span>
        ${navItem('/connections', 'plug', 'Connections', page === 'connections')}
        ${navItem('/system', 'layers', 'Services & health', page === 'system')}
      </div>
      <div class="side-foot"><span class="avatar">${esc((session.username || 'a')[0].toUpperCase())}</span>
        <span style="flex:1;min-width:0;display:flex;flex-direction:column"><span style="font-size:13px;font-weight:600">${esc(session.username || '')}</span><span class="muted" style="font-size:11.5px">${exp == null ? '' : `Session ends in ${exp} h`}</span></span>
        <button class="icon-btn" id="signOut" type="button" aria-label="Sign out">${icon('logout')}</button></div>`;

    document.getElementById('signOut').onclick = async () => { await fetch('/api/logout', { method: 'POST' }); location.href = '/login'; };
    const search = document.getElementById('navSearch');
    search.addEventListener('input', () => {
      const q = search.value.trim().toLowerCase();
      side.querySelectorAll('.nav-item, .nav-sub a').forEach((a) => { a.hidden = q && !a.dataset.label.includes(q); });
      side.querySelectorAll('.nav-group').forEach((g) => { g.hidden = q && !g.querySelector('.nav-item:not([hidden]), .nav-sub a:not([hidden])'); });
    });
    search.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { const first = side.querySelector('.nav-item:not([hidden])'); if (first) location.href = first.getAttribute('href'); }
      if (e.key === 'Escape') { search.value = ''; search.dispatchEvent(new Event('input')); search.blur(); }
    });
    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); side.classList.add('open'); search.focus(); }
    });

    // Small-screen menu bar.
    if (!document.querySelector('.mobile-bar')) {
      const bar = document.createElement('div');
      bar.className = 'mobile-bar';
      bar.innerHTML = `<a class="brand" href="/"><span class="brand-mark">AI</span><span class="brand-name">TrendAI <span>Demo Platform</span></span></a><button class="icon-btn" type="button" aria-label="Menu" aria-expanded="false">${icon('menu')}</button>`;
      side.parentNode.insertBefore(bar, side);
      bar.querySelector('button').onclick = (ev) => { const open = side.classList.toggle('open'); ev.currentTarget.setAttribute('aria-expanded', String(open)); };
    }

    // Activity badge: items blocked in the last 24 h.
    api('/api/activity').then((d) => {
      const n = (d.stats.blockedAiGuard || 0) + (d.stats.blockedFileSecurity || 0);
      const b = document.getElementById('navBlocked');
      if (b && n) { b.textContent = n; b.hidden = false; b.title = `${n} blocked in the last 24 h`; }
    }).catch(() => {});
  }

  async function boot() {
    let session;
    try {
      session = await (await fetch('/api/session')).json();
    } catch (_) { location.href = '/login'; return null; }
    if (!session.authenticated) { location.href = '/login'; return null; }
    if (session.mustChangePassword) { location.href = '/change-password'; return null; }
    renderSide(session);
    return session;
  }

  // ---- Demo Center navigation (industries / solutions / stories) ----
  const IND_ICON = {
    bank: '<path d="M3 10 12 4l9 6"/><path d="M5 10v8M9.5 10v8M14.5 10v8M19 10v8M3 20h18"/>',
    heart: '<path d="M12 21s-7-4.4-9.3-9A5.3 5.3 0 0 1 12 6.6 5.3 5.3 0 0 1 21.3 12C19 16.6 12 21 12 21z"/>',
    factory: '<path d="M3 21V10l6 4V10l6 4V6l6 4v11z"/><path d="M7 17h2M12 17h2M17 17h1"/>',
    cart: '<path d="M4 7h16l-1.5 9h-13z"/><path d="M8 7V5a4 4 0 0 1 8 0v2"/><circle cx="9" cy="20" r="1"/><circle cx="16" cy="20" r="1"/>',
    gov: '<path d="M3 21h18M5 21V10M19 21V10M9 21v-6h6v6"/><path d="M3 10 12 3l9 7z"/>',
  };
  function iconPath(paths, size = 16) {
    return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
  }

  function renderCenterNav(session, active) {
    const side = document.getElementById('side');
    if (!side) return;
    const C = window.TRENDAI_CENTER || { INDUSTRIES: [], SOLUTIONS: [] };
    const host = session.hostLabel || location.host;
    const link = (href, inner, on) => `<a class="nav-item${on ? ' active' : ''}" href="${href}"${on ? ' aria-current="page"' : ''}>${inner}</a>`;
    const ind = C.INDUSTRIES.map((i) => link(`/industry/${i.id}`,
      `<span style="width:8px;height:8px;border-radius:2px;background:${i.color};flex-shrink:0"></span><span class="grow">${esc(i.name)}</span>`,
      active.type === 'industry' && active.id === i.id)).join('');
    const sol = C.SOLUTIONS.map((s) => link(`/solutions#${s.id}`, `<span class="grow">${esc(s.name)}</span>`,
      active.type === 'solutions' && active.id === s.id)).join('');
    side.innerHTML = `
      <a class="brand" href="/"><span class="brand-mark">AI</span><span style="min-width:0"><span class="brand-name">TrendAI <span>Demo Center</span></span><span class="brand-host">${esc(host)}</span></span></a>
      <label class="side-search">${icon('search')}<input type="search" id="navSearch" aria-label="Search stories, industries and tools" placeholder="Search"></label>
      <div class="nav-group">
        ${link('/', `${icon('home')}<span class="grow">Home</span>`, active.type === 'home')}
        ${link('/stories', `${iconPath('<path d="M5 4h11l3 3v13H5z"/><path d="M9 9h6M9 13h6M9 17h3"/>')}<span class="grow">All demo stories</span>`, active.type === 'stories')}
      </div>
      <div class="nav-group"><span class="nav-label">Industries</span>${ind}</div>
      <div class="nav-group"><span class="nav-label">Solutions</span>${sol}</div>
      <div class="nav-group"><span class="nav-label">Admin</span>
        ${link('/tools', `${icon('layers')}<span class="grow">All tools</span>`, false)}
        ${link('/connections', `${icon('plug')}<span class="grow">Settings</span>`, false)}
        ${link('/system', `${icon('activity')}<span class="grow">Services &amp; health</span>`, false)}
      </div>
      <div class="side-foot"><span class="avatar">${esc((session.username || 'a')[0].toUpperCase())}</span>
        <span style="flex:1;min-width:0;display:flex;flex-direction:column"><span style="font-size:13px;font-weight:600">${esc(session.username || '')}</span><span class="muted" style="font-size:11.5px">Demo session</span></span>
        <button class="icon-btn" id="signOut" type="button" aria-label="Sign out">${icon('logout')}</button></div>`;
    document.getElementById('signOut').onclick = async () => { await fetch('/api/logout', { method: 'POST' }); location.href = '/login'; };
    const search = document.getElementById('navSearch');
    if (search) search.addEventListener('keydown', (e) => { if (e.key === 'Enter' && search.value.trim()) location.href = '/stories?q=' + encodeURIComponent(search.value.trim()); });
    if (!document.querySelector('.mobile-bar')) {
      const bar = document.createElement('div');
      bar.className = 'mobile-bar';
      bar.innerHTML = `<a class="brand" href="/"><span class="brand-mark">AI</span><span class="brand-name">TrendAI <span>Demo Center</span></span></a><button class="icon-btn" type="button" aria-label="Menu">${icon('menu')}</button>`;
      side.parentNode.insertBefore(bar, side);
      bar.querySelector('button').onclick = () => side.classList.toggle('open');
    }
  }

  async function bootCenter(active) {
    let session;
    try { session = await (await fetch('/api/session')).json(); } catch (_) { location.href = '/login'; return null; }
    if (!session.authenticated) { location.href = '/login'; return null; }
    if (session.mustChangePassword) { location.href = '/change-password'; return null; }
    renderCenterNav(session, active || { type: 'home' });
    return session;
  }
  const IND = (id) => (window.TRENDAI_CENTER || { INDUSTRIES: [] }).INDUSTRIES.find((i) => i.id === id);
  const SOL = (id) => (window.TRENDAI_CENTER || { SOLUTIONS: [] }).SOLUTIONS.find((s) => s.id === id);
  const indIcon = (name, size) => iconPath(IND_ICON[name] || IND_ICON.bank, size);

  window.TA = { icon, esc, api, toast, fmtTime, demos, demoById, toolIdFromPath, boot, renderSide, bootCenter, renderCenterNav, IND, SOL, indIcon };
})();
