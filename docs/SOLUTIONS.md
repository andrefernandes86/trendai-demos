# TrendAI Solutions Demo Center — configuration guidelines

Every solution is activated from one screen: **Admin → Settings** (the central
Connections store). You enter each key, endpoint, URL or token once; the
platform encrypts it at rest (AES-256-GCM in the portal volume) and pushes it to
each tool that needs it over the internal network. Nothing is returned to the
browser; a tool that restarts is re-supplied automatically.

All product names below are the official **Trend Vision One** module names. In
the demo UI they carry the "TrendAI" brand, but the APIs, endpoints and SDKs are
the real Trend Vision One ones.

---

## 1. One API key for most modules

Most Vision One modules authenticate with a **Vision One API key**.

**Where to get it:** Vision One console → **Administration → API Keys & Tokens
→ Add API Key**. Give it a **role** with least privilege for what the demo needs
(table below), set an expiry, and copy the token — it is shown only once.

**Region / base URL** (set once under *TrendAI Vision One → Region*; every
module derives its endpoint from it):

| Region | API base URL | File Security region code |
|---|---|---|
| United States | `https://api.xdr.trendmicro.com` | `us-east-1` |
| Europe | `https://api.eu.xdr.trendmicro.com` | `eu-central-1` |
| Japan | `https://api.xdr.trendmicro.co.jp` | `ap-northeast-1` |
| Singapore | `https://api.sg.xdr.trendmicro.com` | `ap-southeast-1` |
| Australia | `https://api.au.xdr.trendmicro.com` | `ap-southeast-2` |
| India | `https://api.in.xdr.trendmicro.com` | `ap-south-1` |
| Middle East (UAE) | `https://api.mea.xdr.trendmicro.com` | `me-central-1` |

Enter the Vision One key once. **AI Guard** and **File Security** inherit it
unless you give them their own key with a narrower role.

---

## 2. Module-by-module configuration

### AI Security — AI Guard
*Detects and blocks prompt injection, jailbreaks, unsafe content and sensitive-data leaks in prompts, responses, retrieved context, MCP arguments and uploaded document text.*

- **Settings → AI Guard.** Uses the Vision One key, or its own key with the **AI Security** permission.
- **Endpoint:** `https://api.<region>.xdr.trendmicro.com/beta/aiSecurity/guard` (prefilled from the region; override only for a private/preview endpoint).
- **Request limit:** 50 KB per call. Long prompts and documents are split into ≤48 KB chunks with a 400-character overlap; one blocked chunk blocks the item.
- **Options:** chunk size, max chunks, and fail-open vs fail-closed when AI Guard is unreachable.
- **Used by:** the industry AI assistants, AI Target Range, the "Prompt check" and "Document check" quick tools.

### AI Security — AI Scanner (Trend Micro Artifact Scanner, TMAS)
*Runs the real `tmas aiscan llm` battery against a model and maps findings to the OWASP Top 10 for LLM Applications.*

- **Settings → TrendAI Vision One** key (role: **Run artifact scan / AI scan**) plus **Region**. The CLI reads `TMAS_API_KEY` and the region; the platform passes both.
- **Target model:** chosen per scan inside the tool (an LLM endpoint from Settings, or any OpenAI-compatible URL).

### AI Security — ZTSA AI Service Access
*Governs employee use of public AI services and inspects that traffic for prompt injection and data loss.*

- **External/gateway module.** In the demo it appears as a guided story; configure the **Vision One key** and, where a gateway is used, its service URL under *Settings → Demo infrastructure*.

### File Security (File Security SDK)
*Malware + optional Predictive ML scan of every uploaded or scanned file, via the official SDK (`amaas`, gRPC).*

- **Settings → File Security.** Uses the Vision One key or its own key with the **File Security** / run-scan permission.
- **Region:** short code from the table above (`us-east-1`, …). The SDK connects with `init_by_region(region, api_key)`.
- **Options:** Predictive Machine Learning (PML) on/off; fail-closed (reject a file if the scan can't complete).
- **Used by:** File Security Scanner, the "Document check" tool, the AI assistants' uploads, and the cloud file-storage story.

### Network Security — Network Detection & Response / TippingPoint IPS
*A network sensor on the wire detects replayed benign and malicious traffic (exploits, C2, exfiltration, OT protocols).*

- **Settings → Demo infrastructure → Network PCAP replay.** Set the **replay interface** (the host NIC on the monitored segment, e.g. `ens18`). The replay tool emits traffic with `tcpreplay`; detections appear in **your** NDR / Deep Discovery Inspector / TippingPoint console.
- **Prerequisite:** a Trend Vision One Network Security sensor must be monitoring that segment (SPAN/mirror or inline). The demo host only generates the traffic.

### Server & Workload Protection
*Agent-based defense: Anti-Malware, Web Reputation, Intrusion Prevention (virtual patching), Integrity Monitoring, Log Inspection — each catches a stage of a simulated attack, including the Apache Struts exploit.*

- **No key in the portal.** The demo produces **real host activity** (a real EICAR write, a real outbound request, a real exploit request over the wire).
- **To see detections:** a **Server & Workload Protection agent** must be enrolled to your tenant on the demo host. Integrity Monitoring and Log Inspection additionally need a one-time policy rule pointing at the demo path/log (the tool's README gives the exact rule).
- **Settings → Demo infrastructure → Vulnerable API & Struts target:** the lab address the exploit stories run against (lab network only).

### Endpoint Security
*Endpoint Sensor and behaviour monitoring on a managed endpoint.*

- **Agent-based**, same model as Server & Workload Protection: enroll an endpoint agent to your tenant; the stories drive activity that shows in the Vision One **Workbench**.

### Cloud Security — Cloud Posture & Container Security
*Posture/CNAPP findings and runtime container admission control.*

- **Settings → Demo infrastructure → Kubernetes / Container Security.** Provide the **cluster API server URL** and a **service-account token** for the lab cluster. Container Security is installed on that cluster (Helm); the demo deploys vulnerable workloads for it to catch.
- **Cloud Posture / accounts** connect through **Cloud Account Management** in the Vision One console (not a key in the portal).

### File Security — cloud file storage (AWS / Azure)
*Scans objects landing in cloud storage and moves malicious ones aside.*

- **Settings → Demo infrastructure → Cloud file storage.** Provide the **bucket/endpoint** and an **access token/key** for the lab storage account. This is an external lab; the Settings page only holds its address and credential.

### XDR (Workbench) & Threat Intel — via the Vision One MCP server
*Natural-language queries against Workbench alerts, Attack Surface Risk Management (CREM), Cloud Account Management, Endpoint and Container Security.*

- **Settings → Demo infrastructure → Vision One MCP server.** Uses the **Vision One key**; **read-only** by default. Write mode (which can delete objects) needs an explicit opt-in.

### Attack Surface Risk Management — Cyber Risk Exposure Management (CREM)
*Exposure and risk scoring.* Read through the MCP server with the Vision One key; shown as a guided story.

### Agentic SIEM
*Sizing and investigation.* The **SIEM Sizing Calculator** needs no key. Live investigation stories use the Vision One key through XDR/MCP.

---

## 3. LLM endpoints (for the AI assistants and red-team tools)

*Settings → LLM endpoints.* Add any **OpenAI-compatible** server:

- **vLLM / gateway:** base URL ending in `/v1` (e.g. `http://llm-host:8000/v1`), the served model name, and an API key/token if the server requires one. Must support tool calling.
- **Bundled Ollama:** only runs when the `local-llm` Compose profile is enabled; otherwise it stays off and you point at an external server.
- Pick a **default**, and optionally a different endpoint per tool. **Test** checks reachability and that the model is served.

---

## 4. What runs where

| Where | Modules |
|---|---|
| **On the demo host** (Docker Compose) | AI Guard, File Security, AI Scanner, MCP/XDR queries, the AI assistants and AI Target Range, PCAP replay, the vulnerable API and Struts targets, SIEM sizing |
| **Needs a Trend sensor/agent on your side** | Network Security (sensor on the segment), Server & Workload Protection and Endpoint Security (agents enrolled to your tenant) |
| **External lab, address + token entered in Settings** | Container Security (Kubernetes), Cloud Posture, cloud file storage (AWS/Azure), ZTSA |

---

## 5. Safety / exposure

- The vulnerable apps (AI Target Range, vulnerable API, Apache Struts) are **deliberately insecure**. Compose binds them to a **lab LAN address only**; never route them through the public tunnel.
- All companies, people and data in the stories are fictional.
- Set `PLATFORM_SECRET` in `.env` so the encryption key is not stored next to the encrypted keys in the volume.
