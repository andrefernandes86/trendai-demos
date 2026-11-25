# TrendAI Tools

A self-contained, TrendAI Vision One–branded tools hub. It presents a single
**login-gated landing page** with a side menu (**Demo Tools · Business Tools ·
Other**) that launches a set of **tools**, each shipped as its own Docker
container and documented with a short "how to demo" script.

The platform is intentionally read-only: once signed in, a presenter sees the
demo shortcuts and instructions — there is no content-editing surface.

The portal is also a **reverse proxy**: every demo is served on the *same*
origin under a path (`/v1fs`, `/appsec`, `/smish`) and is only reachable after
login. One hostname fronts everything, and nothing is exposed unauthenticated.

```
   browser ──► ┌───────────────────────────────────────────────┐  :8088
               │  Portal — login gate (admin/admin) + hub +      │
               │           reverse proxy (session required)      │
               └───────┬──────────────┬──────────────┬───────────┘
                       │ /v1fs         │ /appsec      │ /smish
                       ▼               ▼              ▼
                 V1 File Scanner   App & File Sec   Smish Detector
                 (internal only)   (internal only)  (internal only)
```

---

## Installing Docker & Docker Compose

You need **Docker Engine** and the **Compose v2 plugin (v2.20+)**. Modern Docker
ships Compose as the `docker compose` subcommand (note: the space — not the old
`docker-compose` binary). Check what you have:

```bash
docker --version
docker compose version   # must be v2.20 or newer
```

### Linux — Ubuntu / Debian (recommended for a lab VM/server)

Install Docker Engine + Compose plugin from Docker's official repository:

```bash
# 1. Remove any distro-shipped old versions
sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# 2. Set up Docker's apt repository
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 3. Install Engine, CLI, and the Compose plugin
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 4. Run docker without sudo (log out/in afterwards for it to take effect)
sudo usermod -aG docker $USER

# 5. Enable + start the daemon
sudo systemctl enable --now docker
```

> **RHEL / CentOS / Rocky / Fedora:** same flow using the `yum`/`dnf` repo — see
> <https://docs.docker.com/engine/install/> and pick your distro.

### macOS

Install **Docker Desktop** (bundles Engine + Compose v2):

```bash
brew install --cask docker      # or download from docker.com
open -a Docker                  # start Docker Desktop, wait for it to say "running"
```

### Windows

Install **Docker Desktop** with the WSL 2 backend:

```powershell
winget install Docker.DockerDesktop
```

Then launch Docker Desktop and wait until it reports it's running. Run the
`docker compose` commands below from **WSL** or PowerShell.

### Verify

```bash
docker run --rm hello-world     # confirms the daemon works
docker compose version          # confirms Compose v2.20+
```

If `docker compose version` reports something older than v2.20 (common on
distro-packaged Docker), install the Compose plugin from Docker's official repo
as shown in the Linux steps above.

---

## Quick start

Requires **Docker** and **Docker Compose v2.20+**.

```bash
git clone https://github.com/andrefernandes86/trendai-demos.git
cd trendai-demos
cp .env.example .env          # optional — sane defaults are baked in
docker compose up -d --build
```

Then open the portal:

```
http://localhost:8088
```

Log in with the default credentials **`admin` / `admin`**. On first login you are
**forced to set a new password** before the demo hub unlocks. The new password is
hashed (scrypt) and stored in the `portal_data` Docker volume, so it survives
restarts.

---

## What's included

Only the portal is published on the host (`8088`). The one deliberate exception
is the AI Target Range's vulnerable app on `8090`, published without login so a
red-team tool can attack it. Keep it on a lab network (see `AI_TARGET_BIND`). Each demo runs in its own
container on the internal network and is reached **through** the portal, under a
path, only after logging in.

| Demo | Container | Path (behind login) | Purpose |
|------|-----------|---------------------|---------|
| **Portal** | `portal` | `/` | Login gate + demo hub + reverse proxy (this app) |
| **TrendAI Vision One File Security** | `v1fs-scanner` | `/v1fs` | Use case: scan file servers / network shares for malware via the File Security SDK; PDF reports |
| **TrendAI Vision One AI Guard & File Security** | `app-sec` + `ollama` | `/appsec` | Use case: an AI chatbot with file uploads — AI Guard screens prompts, File Security scans files |
| **Server & Workload Protection** | `workload-protection` | `/workload` | Use case: agent-based workload defense — Anti-Malware, Web Reputation, Host IPS, Integrity Monitoring, Log Inspection each catch a stage of a simulated attack |
| **AI Scanner** | `ai-scanner` + `ollama` | `/aiscanner` | Use case: red-team a local LLM — real adversarial prompts against a real Ollama model, findings mapped to the OWASP Top 10 for LLM Applications |
| **Smish Detector** | `smish` | `/smish` | Smishing (SMS phishing) awareness demo (under **Other**) |
| **Vision One Chatbot** | `v1-chatbot` | `/v1chat` | Chat front-end driving the real Vision One MCP server |
| **AI Target Range** | `ai-target` + `ollama` | `/aitarget` (control) · `:8090` (target, **no login**) | Use case: realistic, deliberately vulnerable AI assistants for a bank and a hospital, built for AI red-team tools such as Vantyr. 18 switchable weaknesses with an answer key and live hit log, protectable with AI Guard + File Security |
| **Agentic SIEM Sizing Calculator** | `siem-calc` | `/siemcalc` | Credit-sizing wizard for Vision One Agentic SIEM (under **Business Tools**) |

Each demo's live "how to run it" script is shown directly on its card in the portal.

### How the reverse proxy works

- `/v1fs`, `/appsec`, `/smish`, `/workload`, `/siemcalc`, `/aiscanner` proxy to the demo containers with the prefix
  stripped; the portal checks your login session first.
- Each app keeps its own root-absolute asset/API paths (e.g. `/style.css`,
  `/api/scan`). The portal routes those back to the right backend using the
  request `Referer` (with an `x_app` cookie fallback), so the apps run unchanged.
- The Smish (Flask) app is made prefix-aware via `X-Forwarded-Prefix` +
  `ProxyFix` so its multi-page navigation stays under `/smish`.

---

## The platform shell

After signing in, everything happens in one shell with a single side menu (no top tabs):

| Page | What it does |
|---|---|
| **Home** (`/`) | Connection status, every tool with what it uses and whether it is running, recent activity |
| **Tools** (`/tool/<id>`) | Each tool opens inside the shell. Tools that declare `sections` in `portal/public/demos.js` (today: AI Target Range) hide their own menu and expose those sections as side-menu sub-items |
| **Activity** (`/activity`) | One feed across tools with what TrendAI decided (AI Guard, File Security, weakness hits), filters and CSV export |
| **Connections** (`/connections`) | Vision One, AI Guard, File Security keys and LLM endpoints, entered once |
| **Services & health** (`/system`) | Reachability of every service, version, active Compose profiles, exposure warnings |

The design system lives in `portal/public/ui/trendai.css` (Vantyr-aligned tokens: near-black blue bases, cyan accent, Inter + JetBrains Mono) and `portal/public/ui/shell.js` (session guard + side menu). Tools can link the stylesheet to match.

### Connections: keys entered once

Keys are stored **encrypted** (AES-256-GCM) in the `portal_data` volume and never sent back to the browser. Set `PLATFORM_SECRET` in `.env` to keep the encryption key out of that volume.

The portal **pushes** the settings into each tool through the tool's existing settings API, so no tool needs a code change. It checks every minute and pushes again after a tool restarts and loses its in-memory keys. The *Delivery to tools* table shows the result per tool.

| Tool | Receives |
|---|---|
| File Security Scanner | File Security key and region (skipped when it is set to a local scanner) |
| AI Guard & File Security | AI Guard key and endpoint, File Security key and region, and the LLM when it is an Ollama server |
| AI Scanner | Vision One key and region (its target model is chosen per scan) |
| Vision One Chatbot | Vision One key and region, LLM endpoint |
| AI Target Range | AI Guard (key, endpoint, chunking, fail mode), File Security, LLM endpoint |

AI Guard and File Security fall back to the Vision One key when they have none of their own. Each key has a **Test** button. File Security is tested through the File Security Scanner tool, because the portal itself has no SDK.

Connections is the source of truth: a key typed into a tool's own settings is replaced at the next push.

### Using an external LLM (vLLM or another Ollama)

1. In **Connections → LLM endpoints**, add the endpoint (for vLLM, the `/v1` URL and the served model name), make it the default and click **Test**. Or pre-seed it with `PLATFORM_LLM_URL` / `PLATFORM_LLM_PROVIDER` / `PLATFORM_LLM_MODEL` in `.env`.
2. Leave `local-llm` out of `COMPOSE_PROFILES` so the bundled Ollama container doesn't start.

## Prerequisites for individual demos

The demos **start** without any keys; the Vision One / AI features simply stay
inert until configured.

- **TrendAI Vision One File Security** — enter your Vision One File Security
  **API key + region** in the tool's own Settings UI (persisted to its volume).
- **TrendAI Vision One AI Guard & File Security** — a bundled **Ollama**
  container (model `gemma2:2b`, CPU) is included and pre-wired at
  `http://ollama:11434`, so the chatbot works out of the box. Enter your Vision
  One **AI Guard** and **File Security** API keys in Settings to enable
  detection. Override the model with `OLLAMA_MODEL` (e.g. `llama3.2:1b` for a
  faster CPU response) in `.env`.
- **AI Target Range**: uses the bundled Ollama with `qwen2.5:3b` (tool calling
  is required). For realistic agent behaviour, point it at a bigger Ollama or a
  vLLM server (`AI_TARGET_LLM_URL`, `AI_TARGET_MODEL` in `.env`, or the control
  panel). See `tools/ai-target/README.md`.
- **Smish Detector** — none. Report password defaults to `sms`
  (`REPORT_PASSWORD` in `.env`). Educational use, controlled environments only.

---

## Putting it behind Cloudflare (one hostname, shared login)

Because everything is same-origin behind the portal, exposing the platform is
simple: point **one** Cloudflare tunnel Public Hostname at the portal.

| Public hostname | Service (origin) |
|-----------------|------------------|
| `trendai.<domain>` | `http://<host-ip>:8088` |

That's it — the demos are served under `trendai.<domain>/v1fs`, `/appsec`,
`/smish`, all gated by the portal login. No per-demo DNS, no extra ports, and it
all runs over standard HTTPS/443 so it passes through corporate web proxies.

---

## Resetting the portal password

The password lives only in the `portal_data` volume. To return to the default
`admin / admin` (and re-trigger the forced reset):

```bash
docker compose down
docker volume rm trendai-demo_portal_data
docker compose up -d
```

---

## Repository layout

```
trendai-demo/
├── docker-compose.yml         # top-level orchestration (portal + 3 demos)
├── .env.example
├── portal/                    # branded login gate + demo hub + reverse proxy (Node/Express)
│   ├── server.js              #   auth, forced reset, page routing, platform APIs, demo proxy
│   ├── connections.js         #   encrypted Connections store + push-to-tool connectors
│   ├── platform.js            #   Activity feed + Services & health probes
│   ├── Dockerfile
│   └── public/                #   shell pages, demos.js (tool catalogue), ui/ design system
└── tools/                     # vendored copies of each demo application
    ├── v1fs-manual-scan/      #   TrendAI Vision One File Security scanner (Go)
    ├── app-sec-file-sec/      #   AI Guard & File Security chatbot (FastAPI + Ollama)
    ├── workload-protection/   #   Server & Workload Protection demo (FastAPI)
    ├── ai-scanner/            #   AI Scanner — LLM red-teaming demo (FastAPI + Ollama)
    ├── v1-chatbot/            #   Vision One Chatbot over the real MCP server (FastAPI + Go)
    ├── ai-target/             #   AI Target Range — vulnerable bank + hospital AI apps (FastAPI)
    ├── sms-dl/                #   Smish Detector (Flask)
    └── siem-calculator/       #   Agentic SIEM Sizing Calculator (nginx SPA)
```

Each folder under `tools/` is a copy of its upstream repository, kept intact so
its own README and Dockerfile remain the source of truth for that tool.

---

## Notes

- **Sales enablement / demonstration use.** The Smish Detector is for security
  **awareness training in controlled environments only**.
- The portal exposes no editing capability by design — it is a presenter's
  launchpad, not an admin console.
- To customise which demos appear or their instructions, edit
  `portal/public/demos.js` and rebuild the `portal` service.
