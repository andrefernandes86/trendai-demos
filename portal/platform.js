'use strict';

/**
 * Platform-wide Activity feed and Services & health.
 *
 * Activity merges the portal's own events (sign-ins, Connections changes and
 * pushes) with every tool that exposes an event feed. Today that is the AI
 * Target Range; other tools join by adding a feed adapter below.
 *
 * Health probes each service over the compose network. The portal has no
 * Docker socket (on purpose), so it reports reachability, not container state.
 */

const { request, svcUrl } = require('./connections');

const SERVICES = [
  { id: 'portal', name: 'portal', profile: 'core', exposure: 'published :8088 (login)', url: null },
  { id: 'v1fs', name: 'v1fs-scanner', profile: 'core', exposure: 'internal', url: svcUrl('v1fs', 'http://v1fs-scanner:8080') + '/' },
  { id: 'appsec', name: 'app-sec', profile: 'core', exposure: 'internal', url: svcUrl('appsec', 'http://app-sec:8000') + '/' },
  { id: 'workload', name: 'workload-protection', profile: 'core', exposure: 'internal · /opt/workload-demo', url: svcUrl('workload', 'http://workload-protection:8000') + '/' },
  { id: 'aiscanner', name: 'ai-scanner', profile: 'core', exposure: 'internal', url: svcUrl('aiscanner', 'http://ai-scanner:8000') + '/' },
  { id: 'v1chat', name: 'v1-chatbot', profile: 'core', exposure: 'internal', url: svcUrl('v1chat', 'http://v1-chatbot:8000') + '/' },
  { id: 'aitarget', name: 'ai-target', profile: 'core', exposure: 'published :8090 — no login, lab network only', warn: true, url: svcUrl('aitarget', 'http://ai-target:8000') + '/healthz' },
  { id: 'siemcalc', name: 'siem-calc', profile: 'core', exposure: 'internal', url: svcUrl('siemcalc', 'http://siem-calc:80') + '/' },
  { id: 'smish', name: 'smish', profile: 'core', exposure: 'internal', url: svcUrl('smish', 'https://smish:5000') + '/' },
  { id: 'ollama', name: 'ollama', profile: 'local-llm', exposure: 'internal', url: svcUrl('ollama', 'http://ollama:11434') + '/api/tags' },
];

const TENANT = { finance: 'Northbridge Bank', healthcare: 'Meridian Health', host: 'Host' };

class Platform {
  constructor() {
    this.events = []; // portal-originated events, newest first
    this.started = Date.now();
  }

  log({ tool = 'platform', label = '', kind = 'info', event, detail = '', source = '' }) {
    this.events.unshift({ ts: Date.now() / 1000, toolId: tool, tool: label || (tool === 'platform' ? 'Platform' : tool), kind, event, detail, source });
    if (this.events.length > 500) this.events.length = 500;
  }

  async aiTargetEvents() {
    const r = await request(svcUrl('aitarget', 'http://ai-target:8000') + '/admin/api/events', { timeout: 4000 });
    if (!r.ok || !r.json) return { ok: false, events: [] };
    const out = r.json.events.map((e) => {
      const prot = e.protection || [];
      const blockedBy = prot.find((p) => p.verdict === 'block');
      let kind = 'info';
      let outcome = 'Allowed';
      if (e.blocked) {
        kind = 'blocked';
        outcome = blockedBy ? `Blocked · ${blockedBy.engine === 'ai_guard' ? 'AI Guard' : 'File Security'}${blockedBy.chunks > 1 ? ` · chunk ${(blockedBy.blocked_chunks || [0])[0] + 1} of ${blockedBy.chunks}` : ''}`
          : `Blocked · ${e.blocked_by || 'guardrail'}`;
        if (blockedBy && blockedBy.engine === 'file_security' && /malware/i.test(blockedBy.reason || '')) outcome = blockedBy.reason;
      } else if (e.error) {
        kind = 'warn'; outcome = 'Error';
      } else if ((e.hits || []).length) {
        kind = 'finding'; outcome = 'Weakness hit · ' + e.hits.join(', ');
      } else if (prot.some((p) => p.verdict === 'error' || p.verdict === 'partial')) {
        kind = 'warn'; outcome = 'Inspected partially (fail-open)';
      }
      return { ts: e.ts, toolId: 'aitarget', tool: 'AI Target Range', kind, outcome, source: e.ip,
        event: `${e.channel} · ${TENANT[e.tenant] || e.tenant}: ${String(e.input || '').slice(0, 160)}`,
        engines: prot.map((p) => ({ engine: p.engine, stage: p.stage, verdict: p.verdict })) };
    });
    return { ok: true, events: out };
  }

  async activity({ tool, kind, q, limit = 300 } = {}) {
    const sources = [{ id: 'platform', label: 'Platform', ok: true }];
    const at = await this.aiTargetEvents();
    sources.push({ id: 'aitarget', label: 'AI Target Range', ok: at.ok });
    const portal = this.events.map((e) => ({ ...e, outcome: e.kind === 'warn' ? 'Warning' : (e.kind === 'blocked' ? 'Blocked' : 'Info') }));
    let all = [...at.events, ...portal].sort((a, b) => b.ts - a.ts);
    const dayAgo = Date.now() / 1000 - 86400;
    const today = all.filter((e) => e.ts >= dayAgo);
    const stats = {
      events: today.length,
      blockedAiGuard: today.filter((e) => e.kind === 'blocked' && /AI Guard/.test(e.outcome)).length,
      blockedFileSecurity: today.filter((e) => e.kind === 'blocked' && /File Security|malware/i.test(e.outcome)).length,
      findings: today.filter((e) => e.kind === 'finding').length,
    };
    if (tool) all = all.filter((e) => e.toolId === tool);
    if (kind) all = all.filter((e) => e.kind === kind);
    if (q) { const s = q.toLowerCase(); all = all.filter((e) => `${e.event} ${e.outcome} ${e.source} ${e.detail}`.toLowerCase().includes(s)); }
    return { stats, sources, events: all.slice(0, limit) };
  }

  async health() {
    const results = await Promise.all(SERVICES.map(async (s) => {
      if (!s.url) return { ...s, status: 'healthy', ms: 0, uptime: Math.round((Date.now() - this.started) / 1000) };
      const r = await request(s.url, { timeout: 3000 });
      const up = r.status > 0 && r.status < 500;
      return { ...s, status: up ? 'healthy' : (r.status ? 'unhealthy' : 'unreachable'), httpStatus: r.status, ms: r.ms, error: up ? undefined : r.error };
    }));
    return {
      version: process.env.PLATFORM_VERSION || require('./package.json').version,
      revision: process.env.PLATFORM_REVISION || '',
      profiles: (process.env.COMPOSE_PROFILES || '').split(',').map((p) => p.trim()).filter(Boolean),
      host: process.env.PLATFORM_HOST_LABEL || '',
      services: results,
    };
  }
}

module.exports = { Platform, SERVICES };
