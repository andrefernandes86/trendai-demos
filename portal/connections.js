'use strict';

/**
 * Platform Connections — the single place where TrendAI Vision One keys and
 * LLM endpoints are configured for every tool.
 *
 *  - Stored encrypted at rest (AES-256-GCM) in the portal data volume. The key
 *    comes from PLATFORM_SECRET, or — if unset — from a random key file created
 *    in the same volume (protects against casual reads of the JSON, not against
 *    someone who already has the whole volume; set PLATFORM_SECRET for that).
 *  - Never returned to the browser in plaintext: the UI only sees "set" + last 4.
 *  - Pushed into each tool through that tool's existing settings API (no tool
 *    has to change). A sync loop re-pushes when a tool restarts and comes back
 *    without its in-memory keys, or when the connections change.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const REGIONS = {
  us: { label: 'United States', api: 'https://api.xdr.trendmicro.com', aws: 'us-east-1' },
  eu: { label: 'Europe', api: 'https://api.eu.xdr.trendmicro.com', aws: 'eu-central-1' },
  jp: { label: 'Japan', api: 'https://api.xdr.trendmicro.co.jp', aws: 'ap-northeast-1' },
  sg: { label: 'Singapore', api: 'https://api.sg.xdr.trendmicro.com', aws: 'ap-southeast-1' },
  au: { label: 'Australia', api: 'https://api.au.xdr.trendmicro.com', aws: 'ap-southeast-2' },
  in: { label: 'India', api: 'https://api.in.xdr.trendmicro.com', aws: 'ap-south-1' },
  mea: { label: 'Middle East', api: 'https://api.mea.xdr.trendmicro.com', aws: 'me-central-1' },
};
const FS_REGIONS = ['us-east-1', 'eu-central-1', 'eu-west-2', 'ca-central-1', 'ap-northeast-1', 'ap-southeast-1',
  'ap-southeast-2', 'ap-south-1', 'me-central-1', 'af-south-1', 'ap-southeast-3'];
const AI_GUARD_PATH = '/beta/aiSecurity/guard';
const PROVIDERS = ['ollama', 'vllm', 'openai'];
const BUNDLED_OLLAMA = 'http://ollama:11434';

/** Internal service URL, overridable with PLATFORM_URL_<ID> (e.g. PLATFORM_URL_AITARGET) for non-compose setups. */
function svcUrl(id, fallback) { return process.env['PLATFORM_URL_' + id.toUpperCase()] || fallback; }

// Tools that consume an LLM, and what they can talk to.
const LLM_TOOLS = {
  appsec: { label: 'AI Guard & File Security', providers: ['ollama'], note: 'Needs an Ollama server (uses the Ollama chat API).' },
  v1chat: { label: 'Vision One Chatbot', providers: PROVIDERS, note: 'Needs tool calling.' },
  aitarget: { label: 'AI Target Range', providers: PROVIDERS, note: 'Needs tool calling.' },
};

function defaults() {
  const endpoints = [{ id: 'bundled-ollama', name: 'Bundled Ollama', provider: 'ollama', baseUrl: BUNDLED_OLLAMA,
    model: process.env.OLLAMA_MODEL || 'gemma2:2b', apiKey: '' }];
  let defaultId = 'bundled-ollama';
  if (process.env.PLATFORM_LLM_URL) {
    endpoints.unshift({ id: 'external', name: 'External LLM', provider: process.env.PLATFORM_LLM_PROVIDER || 'vllm',
      baseUrl: process.env.PLATFORM_LLM_URL, model: process.env.PLATFORM_LLM_MODEL || '', apiKey: '' });
    defaultId = 'external';
  }
  return {
    visionOne: { apiKey: '', region: 'us' },
    aiGuard: { apiKey: '', url: '', maxKb: 48, maxChunks: 64, failClosed: false },
    fileSecurity: { apiKey: '', region: 'us-east-1', pml: true, failClosed: true },
    llm: { endpoints, defaultId, assignments: {} },
    // External labs and host-dependent demo tools: addresses and tokens only.
    demoInfra: {
      replayIface: process.env.PLATFORM_REPLAY_IFACE || '',
      targetBaseUrl: process.env.AI_TARGET_PUBLIC_URL || '',
      k8sUrl: '', k8sToken: '',
      cloudStorageUrl: '', cloudStorageToken: '',
      mcpReadOnly: true,
    },
    updatedAt: null,
  };
}

// ---------------------------------------------------------------------------
// Encrypted store
// ---------------------------------------------------------------------------

class ConnectionStore {
  constructor(dir) {
    this.dir = dir;
    this.file = path.join(dir, 'connections.enc.json');
    this.key = this._key();
    this.data = this._load();
  }

  _key() {
    if (process.env.PLATFORM_SECRET) {
      this.keySource = 'PLATFORM_SECRET';
      return crypto.createHash('sha256').update(process.env.PLATFORM_SECRET).digest();
    }
    const kf = path.join(this.dir, '.platform-key');
    fs.mkdirSync(this.dir, { recursive: true });
    if (!fs.existsSync(kf)) fs.writeFileSync(kf, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
    this.keySource = 'volume key file';
    return Buffer.from(fs.readFileSync(kf, 'utf8').trim(), 'hex');
  }

  _load() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(raw.iv, 'base64'));
      decipher.setAuthTag(Buffer.from(raw.tag, 'base64'));
      const plain = Buffer.concat([decipher.update(Buffer.from(raw.data, 'base64')), decipher.final()]).toString('utf8');
      return merge(defaults(), JSON.parse(plain));
    } catch (e) {
      if (fs.existsSync(this.file)) console.error(`[connections] could not decrypt ${this.file}: ${e.message} — starting empty`);
      return defaults();
    }
  }

  save() {
    fs.mkdirSync(this.dir, { recursive: true });
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    const data = Buffer.concat([cipher.update(JSON.stringify(this.data), 'utf8'), cipher.final()]);
    const out = { v: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
    fs.writeFileSync(this.file + '.tmp', JSON.stringify(out), { mode: 0o600 });
    fs.renameSync(this.file + '.tmp', this.file);
  }

  /** Browser-safe view: keys replaced by {set, hint}. */
  masked() {
    const d = JSON.parse(JSON.stringify(this.data));
    const m = (o) => { const k = o.apiKey || ''; delete o.apiKey; o.apiKeySet = !!k; o.apiKeyHint = k ? '••••' + k.slice(-4) : ''; };
    m(d.visionOne); m(d.aiGuard); m(d.fileSecurity);
    d.llm.endpoints.forEach(m);
    const tok = (o, k) => { const v = o[k] || ''; delete o[k]; o[k + 'Set'] = !!v; o[k + 'Hint'] = v ? '••••' + v.slice(-4) : ''; };
    tok(d.demoInfra, 'k8sToken'); tok(d.demoInfra, 'cloudStorageToken');
    const r = resolve(this.data);
    d.effective = { aiGuardUrl: r.agUrl, aiGuardKeyFrom: this.data.aiGuard.apiKey ? 'own' : (r.agKey ? 'visionOne' : 'none'),
      fileSecurityKeyFrom: this.data.fileSecurity.apiKey ? 'own' : (r.fsKey ? 'visionOne' : 'none') };
    d.meta = { regions: Object.fromEntries(Object.entries(REGIONS).map(([k, v]) => [k, { label: v.label, api: v.api }])),
      fsRegions: FS_REGIONS, providers: PROVIDERS, llmTools: LLM_TOOLS, keySource: this.keySource };
    return d;
  }

  /** Apply a partial update from the UI. Blank key fields keep the stored key; clear=true removes it. */
  update(p) {
    const d = this.data;
    const setKey = (target, src) => {
      if (!src) return;
      if (src.clearKey) target.apiKey = '';
      else if (typeof src.apiKey === 'string' && src.apiKey.trim()) target.apiKey = src.apiKey.trim();
    };
    if (p.visionOne) {
      setKey(d.visionOne, p.visionOne);
      if (REGIONS[p.visionOne.region]) d.visionOne.region = p.visionOne.region;
    }
    if (p.aiGuard) {
      setKey(d.aiGuard, p.aiGuard);
      if (typeof p.aiGuard.url === 'string') {
        const u = p.aiGuard.url.trim();
        if (u && !/^https:\/\//.test(u)) throw new Error('AI Guard endpoint must start with https://');
        d.aiGuard.url = u;
      }
      if (p.aiGuard.maxKb != null) d.aiGuard.maxKb = clamp(+p.aiGuard.maxKb, 4, 50);
      if (p.aiGuard.maxChunks != null) d.aiGuard.maxChunks = clamp(+p.aiGuard.maxChunks, 1, 500);
      if (p.aiGuard.failClosed != null) d.aiGuard.failClosed = !!p.aiGuard.failClosed;
    }
    if (p.fileSecurity) {
      setKey(d.fileSecurity, p.fileSecurity);
      if (FS_REGIONS.includes(p.fileSecurity.region)) d.fileSecurity.region = p.fileSecurity.region;
      if (p.fileSecurity.pml != null) d.fileSecurity.pml = !!p.fileSecurity.pml;
      if (p.fileSecurity.failClosed != null) d.fileSecurity.failClosed = !!p.fileSecurity.failClosed;
    }
    if (p.llm) {
      if (Array.isArray(p.llm.endpoints)) {
        const old = Object.fromEntries(d.llm.endpoints.map((e) => [e.id, e]));
        d.llm.endpoints = p.llm.endpoints.slice(0, 20).map((e, i) => {
          const id = String(e.id || '').replace(/[^a-z0-9-]/gi, '').slice(0, 40) || `ep-${Date.now().toString(36)}-${i}`;
          const provider = PROVIDERS.includes(e.provider) ? e.provider : 'openai';
          const baseUrl = String(e.baseUrl || '').trim().replace(/\/+$/, '');
          if (!/^https?:\/\//.test(baseUrl)) throw new Error(`Endpoint "${e.name || id}" needs an http(s) URL`);
          const ep = { id, name: String(e.name || id).slice(0, 60), provider, baseUrl, model: String(e.model || '').trim().slice(0, 120),
            apiKey: (old[id] && old[id].apiKey) || '' };
          setKey(ep, e);
          return ep;
        });
        if (!d.llm.endpoints.length) d.llm.endpoints = defaults().llm.endpoints;
      }
      const ids = d.llm.endpoints.map((e) => e.id);
      if (p.llm.defaultId && ids.includes(p.llm.defaultId)) d.llm.defaultId = p.llm.defaultId;
      if (!ids.includes(d.llm.defaultId)) d.llm.defaultId = ids[0];
      if (p.llm.assignments) {
        for (const [tool, ep] of Object.entries(p.llm.assignments)) {
          if (!LLM_TOOLS[tool]) continue;
          if (!ep || ep === 'default') delete d.llm.assignments[tool];
          else if (ids.includes(ep)) d.llm.assignments[tool] = ep;
        }
      }
      for (const [tool, ep] of Object.entries(d.llm.assignments)) if (!ids.includes(ep)) delete d.llm.assignments[tool];
    }
    if (p.demoInfra) {
      const di = d.demoInfra, pi = p.demoInfra;
      for (const k of ['replayIface', 'targetBaseUrl', 'k8sUrl', 'cloudStorageUrl']) {
        if (typeof pi[k] === 'string') di[k] = pi[k].trim().slice(0, 300);
      }
      for (const k of ['k8sToken', 'cloudStorageToken']) {
        if (pi[k + 'Clear']) di[k] = '';
        else if (typeof pi[k] === 'string' && pi[k].trim()) di[k] = pi[k].trim();
      }
      if (pi.mcpReadOnly != null) di.mcpReadOnly = !!pi.mcpReadOnly;
    }
    d.updatedAt = new Date().toISOString();
    this.save();
  }
}

function clamp(n, lo, hi) { return Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : lo; }

function merge(base, over) {
  for (const [k, v] of Object.entries(over || {})) {
    if (v && typeof v === 'object' && !Array.isArray(v) && base[k] && typeof base[k] === 'object') merge(base[k], v);
    else base[k] = v;
  }
  return base;
}

/** Effective values with fallbacks: AI Guard / File Security keys default to the Vision One key. */
function resolve(d) {
  const region = REGIONS[d.visionOne.region] || REGIONS.us;
  const v1Key = d.visionOne.apiKey;
  return {
    v1Key, region, regionId: d.visionOne.region,
    agKey: d.aiGuard.apiKey || v1Key,
    agUrl: d.aiGuard.url || region.api + AI_GUARD_PATH,
    fsKey: d.fileSecurity.apiKey || v1Key,
    fsRegion: d.fileSecurity.region,
    llmFor: (tool) => {
      const id = d.llm.assignments[tool] || d.llm.defaultId;
      return d.llm.endpoints.find((e) => e.id === id) || d.llm.endpoints[0];
    },
  };
}

// ---------------------------------------------------------------------------
// Small HTTP helper (works for self-signed internal HTTPS too)
// ---------------------------------------------------------------------------

function request(url, { method = 'GET', headers = {}, body, timeout = 8000 } = {}) {
  return new Promise((resolveP) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const data = body == null ? null : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const t0 = Date.now();
    const req = mod.request(u, {
      // Compose service names (no dot, e.g. the self-signed "smish") skip TLS verification; everything else verifies.
      method, timeout, rejectUnauthorized: u.hostname.includes('.'),
      headers: { ...(data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {}), ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => { if (chunks.length < 2000) chunks.push(c); });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (_) { /* not json */ }
        resolveP({ ok: res.statusCode < 400, status: res.statusCode, text, json, ms: Date.now() - t0 });
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => resolveP({ ok: false, status: 0, error: e.message, ms: Date.now() - t0 }));
    if (data) req.write(data);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Connectors — map Connections onto each tool's existing settings API
// ---------------------------------------------------------------------------

function openaiBase(ep) {
  // OpenAI-compatible base for an endpoint (Ollama exposes one under /v1).
  const b = ep.baseUrl.replace(/\/+$/, '');
  return /\/v1$/.test(b) ? b : b + '/v1';
}

const CONNECTORS = {
  v1fs: {
    label: 'File Security Scanner', base: svcUrl('v1fs', 'http://v1fs-scanner:8080'), uses: ['fileSecurity'],
    async read() { return request(this.base + '/api/config'); },
    desired(r) { return r.fsKey ? { apiKey: r.fsKey, region: r.fsRegion } : null; },
    unconfigured(cur) { return !cur.apiKeySet; },
    async push(want, cur) {
      if (cur.scannerType === 'local') return { skipped: 'uses a local scanner, left as is' };
      return request(this.base + '/api/config', { method: 'POST', body: {
        apiKey: want.apiKey, region: want.region, scannerType: 'saas',
        actionOnMalware: cur.actionOnMalware || 'log', quarantinePath: cur.quarantinePath || '' } });
    },
  },
  appsec: {
    label: 'AI Guard & File Security', base: svcUrl('appsec', 'http://app-sec:8000'), uses: ['aiGuard', 'fileSecurity', 'llm'],
    async read() { return request(this.base + '/api/config'); },
    desired(r) {
      const ep = r.llmFor('appsec');
      const ollama = ep && ep.provider === 'ollama';
      if (!r.agKey && !r.fsKey && !ollama) return null;
      return { agKey: r.agKey, agUrl: r.agUrl, fsKey: r.fsKey, fsRegion: r.fsRegion,
        ollamaUrl: ollama ? ep.baseUrl : null, ollamaModel: ollama ? ep.model : null };
    },
    unconfigured(cur, want) { return (want.agKey && !cur.v1_guard_api_key_set) || (want.fsKey && !cur.v1fs_api_key_set); },
    async push(want, cur) {
      // This tool's update replaces the whole config, so carry its other settings over.
      return request(this.base + '/api/config', { method: 'POST', body: {
        ollama_base_url: want.ollamaUrl || cur.ollama_base_url || '', ollama_model: want.ollamaModel || cur.ollama_model || '',
        v1_guard_api_key: want.agKey || '', v1_guard_url_base: want.agUrl, v1_guard_enabled: cur.v1_guard_enabled !== false,
        v1_guard_detailed: !!cur.v1_guard_detailed, enforce_side: cur.enforce_side || 'both',
        v1fs_api_key: want.fsKey || '', v1fs_region: want.fsRegion, v1fs_enabled: cur.v1fs_enabled !== false } });
    },
  },
  aiscanner: {
    label: 'AI Scanner', base: svcUrl('aiscanner', 'http://ai-scanner:8000'), uses: ['visionOne'],
    async read() { return request(this.base + '/api/settings'); },
    desired(r) { return r.v1Key ? { apiKey: r.v1Key, region: r.region.aws } : null; },
    unconfigured(cur) { return !cur.hasApiKey; },
    async push(want) { return request(this.base + '/api/settings', { method: 'POST', body: want }); },
  },
  v1chat: {
    label: 'Vision One Chatbot', base: svcUrl('v1chat', 'http://v1-chatbot:8000'), uses: ['visionOne', 'llm'],
    async read() {
      const [a, b] = await Promise.all([request(this.base + '/api/settings/v1'), request(this.base + '/api/settings/llm')]);
      return a.ok && b.ok ? { ok: true, json: { ...a.json, llm: b.json } } : (a.ok ? b : a);
    },
    desired(r) {
      const ep = r.llmFor('v1chat');
      const llm = !ep ? null : (ep.baseUrl === BUNDLED_OLLAMA
        ? { targetType: 'ollama', endpointUrl: '', apiKey: '', model: ep.model }
        : { targetType: 'openai', endpointUrl: openaiBase(ep), apiKey: ep.apiKey || '', model: ep.model });
      if (!r.v1Key && !llm) return null;
      return { v1: r.v1Key ? { apiKey: r.v1Key, region: r.regionId } : null, llm };
    },
    unconfigured(cur, want) { return want.v1 && !cur.hasApiKey; },
    async push(want, cur) {
      if (want.v1) {
        const a = await request(this.base + '/api/settings/v1', { method: 'POST', body: { ...want.v1, readonly: cur.readonly !== false } });
        if (!a.ok) return a;
      }
      if (want.llm) {
        const b = await request(this.base + '/api/settings/llm', { method: 'POST', body: want.llm });
        if (!b.ok) return b;
      }
      return { ok: true };
    },
  },
  aitarget: {
    label: 'AI Target Range', base: svcUrl('aitarget', 'http://ai-target:8000'), uses: ['aiGuard', 'fileSecurity', 'llm'],
    async read() { return request(this.base + '/admin/api/config'); },
    desired(r, d) {
      const ep = r.llmFor('aitarget');
      return {
        trend: {
          ai_guard: { ...(r.agKey ? { key: r.agKey } : {}), region: r.regionId, url: r.agUrl, max_bytes: d.aiGuard.maxKb * 1024,
            max_chunks: d.aiGuard.maxChunks, fail_closed: d.aiGuard.failClosed },
          file_security: { ...(r.fsKey ? { key: r.fsKey } : {}), region: r.fsRegion, pml: d.fileSecurity.pml,
            fail_closed: d.fileSecurity.failClosed },
        },
        ...(ep ? { llm: { provider: ep.provider, base_url: ep.baseUrl, model: ep.model, api_key: ep.apiKey || '' } } : {}),
      };
    },
    unconfigured(cur, want) {
      return (want.trend.ai_guard.key && !cur.trend.ai_guard.key_set) || (want.trend.file_security.key && !cur.trend.file_security.key_set);
    },
    async push(want) { return request(this.base + '/admin/api/config', { method: 'POST', body: want }); },
  },
};

class Syncer {
  constructor(store, log) {
    this.store = store;
    this.log = log;
    this.state = {}; // tool -> {status, message, at, fp}
    this.running = false;
  }

  async syncAll(reason = 'interval') {
    if (this.running) return this.state;
    this.running = true;
    try {
      const d = this.store.data;
      const r = resolve(d);
      await Promise.all(Object.entries(CONNECTORS).map(async ([id, c]) => {
        const prev = this.state[id] || {};
        const want = c.desired(r, d);
        if (!want) { this.state[id] = { status: 'idle', message: 'Nothing to configure yet', at: Date.now() }; return; }
        const fp = crypto.createHash('sha256').update(JSON.stringify(want)).digest('hex');
        const cur = await c.read();
        if (!cur.ok) { this.state[id] = { ...prev, status: 'unreachable', message: cur.error || `HTTP ${cur.status}`, at: Date.now() }; return; }
        const needs = fp !== prev.fp || c.unconfigured(cur.json || {}, want);
        if (!needs) { this.state[id] = { ...prev, status: 'in-sync', message: 'Up to date', at: Date.now() }; return; }
        const res = await c.push(want, cur.json || {});
        if (res.skipped) { this.state[id] = { status: 'skipped', message: res.skipped, at: Date.now(), fp }; return; }
        if (res.ok) {
          this.state[id] = { status: 'in-sync', message: 'Settings pushed', at: Date.now(), fp, pushedAt: Date.now() };
          this.log({ tool: id, label: c.label, kind: 'info', event: `Connections pushed to ${c.label}`, detail: reason });
        } else {
          this.state[id] = { status: 'error', message: (res.json && (res.json.detail || res.json.error)) || res.text || res.error || `HTTP ${res.status}`, at: Date.now() };
          this.log({ tool: id, label: c.label, kind: 'warn', event: `Could not push Connections to ${c.label}`, detail: this.state[id].message });
        }
      }));
    } finally {
      this.running = false;
    }
    return this.state;
  }

  status() {
    return Object.fromEntries(Object.entries(CONNECTORS).map(([id, c]) => [id, { label: c.label, uses: c.uses, ...(this.state[id] || { status: 'pending' }) }]));
  }
}

// ---------------------------------------------------------------------------
// Connection tests (run from the portal container)
// ---------------------------------------------------------------------------

async function testConnection(store, kind, endpointId) {
  const d = store.data;
  const r = resolve(d);
  if (kind === 'visionOne') {
    if (!r.v1Key) return { ok: false, message: 'No Vision One API key set' };
    const res = await request(r.region.api + '/v3.0/healthcheck/connectivity', { headers: { Authorization: 'Bearer ' + r.v1Key } });
    return { ok: res.ok, message: res.ok ? `Reached ${r.region.label} in ${res.ms} ms` : `HTTP ${res.status || ''} ${res.error || (res.text || '').slice(0, 160)}`.trim() };
  }
  if (kind === 'aiGuard') {
    if (!r.agKey) return { ok: false, message: 'No AI Guard or Vision One API key set' };
    const res = await request(r.agUrl + '?detailedResponse=false', { method: 'POST', body: { guard: 'Hello, what are your opening hours?' },
      headers: { Authorization: 'Bearer ' + r.agKey, 'TMV1-Application-Name': 'trendai-demo-platform' } });
    const action = res.json && (res.json.action || res.json.decision);
    return { ok: res.ok, message: res.ok ? `AI Guard answered "${action || 'ok'}" in ${res.ms} ms` : `HTTP ${res.status || ''} ${res.error || (res.text || '').slice(0, 160)}`.trim() };
  }
  if (kind === 'fileSecurity') {
    // The portal has no File Security SDK; the File Security Scanner tool tests its (pushed) key.
    const res = await request(CONNECTORS.v1fs.base + '/api/scanner/test', { method: 'POST', body: {}, timeout: 30000 });
    if (!res.ok && !res.status) return { ok: false, message: 'File Security Scanner tool is not reachable to run the test' };
    const j = res.json || {};
    const ok = res.ok && (j.ok === true || j.success === true || j.status === 'ok');
    return { ok, message: ok ? `Scan service reachable (tested by the File Security Scanner) in ${res.ms} ms` : (j.error || j.message || (res.text || '').slice(0, 200) || `HTTP ${res.status}`) };
  }
  if (kind === 'llm') {
    const ep = d.llm.endpoints.find((e) => e.id === endpointId);
    if (!ep) return { ok: false, message: 'Unknown endpoint' };
    const headers = ep.apiKey ? { Authorization: 'Bearer ' + ep.apiKey } : {};
    const res = ep.provider === 'ollama'
      ? await request(ep.baseUrl + '/api/tags', { headers })
      : await request(openaiBase(ep) + '/models', { headers });
    if (!res.ok) return { ok: false, message: `HTTP ${res.status || ''} ${res.error || (res.text || '').slice(0, 160)}`.trim() };
    const models = ep.provider === 'ollama' ? ((res.json && res.json.models) || []).map((m) => m.name)
      : ((res.json && res.json.data) || []).map((m) => m.id);
    const has = !ep.model || models.includes(ep.model) || models.some((m) => m.split(':')[0] === ep.model);
    return { ok: has, models: models.slice(0, 50), ms: res.ms,
      message: has ? `Reachable in ${res.ms} ms · ${models.length} model(s)` : `Reachable, but "${ep.model}" is not served (${models.slice(0, 5).join(', ') || 'no models'})` };
  }
  return { ok: false, message: 'Unknown connection' };
}

module.exports = { ConnectionStore, Syncer, testConnection, request, svcUrl, CONNECTORS, REGIONS };
