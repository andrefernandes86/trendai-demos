"""
TrendAI Vision One protection layer for the AI Target Range.

  * AI Guard        — inspects prompts, model responses, retrieved context, MCP
                      arguments and the TEXT CONTENT of uploaded documents.
  * File Security   — malware (and optional PML) scan of every uploaded file via
                      the official SDK (visionone-filesecurity, amaas.grpc.aio).

AI Guard accepts at most ~50 KB per request. Anything larger (a long prompt, a
40-page PDF) is split into chunks that each fit, with a small overlap so an
instruction that straddles a boundary is still seen whole by at least one
chunk. Every chunk is scanned; one blocked chunk blocks the content. Content
beyond the chunk cap is never silently ignored: it is either blocked
(fail-closed) or explicitly reported as partially inspected.
"""

import asyncio
import collections
import hashlib
import io
import json
import time
from typing import Optional

import httpx

try:
    import amaas.grpc.aio as amaas_aio
    V1FS_AVAILABLE = True
except Exception:  # pragma: no cover - SDK missing in a dev env
    amaas_aio = None
    V1FS_AVAILABLE = False

AI_GUARD_LIMIT_BYTES = 50 * 1024          # documented AI Guard request limit
AI_GUARD_REGIONS = {
    "us": "https://api.xdr.trendmicro.com",
    "eu": "https://api.eu.xdr.trendmicro.com",
    "jp": "https://api.xdr.trendmicro.co.jp",
    "sg": "https://api.sg.xdr.trendmicro.com",
    "au": "https://api.au.xdr.trendmicro.com",
    "in": "https://api.in.xdr.trendmicro.com",
    "mea": "https://api.mea.xdr.trendmicro.com",
}
AI_GUARD_PATH = "/beta/aiSecurity/guard"
V1FS_REGIONS = ["us-east-1", "eu-central-1", "eu-west-2", "ca-central-1", "ap-northeast-1", "ap-southeast-1",
                "ap-southeast-2", "ap-south-1", "me-central-1", "af-south-1", "ap-southeast-3"]

TEXT_EXT = {".txt", ".md", ".csv", ".tsv", ".json", ".xml", ".html", ".htm", ".log", ".yaml", ".yml", ".rtf", ".eml"}
DOC_EXT = {".pdf", ".docx"}
MAX_EXTRACT_CHARS = 2_000_000

_CACHE: "collections.OrderedDict[str, dict]" = collections.OrderedDict()
_CACHE_MAX = 3000
_SEM = asyncio.Semaphore(4)


# =============================================================================
# Text extraction
# =============================================================================

def extract_text(name: str, data: bytes) -> dict:
    """Return {'kind': 'text'|'document'|'binary', 'text': str, 'note': str}."""
    ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    try:
        if ext == ".pdf":
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data))
            text = "\n\n".join((p.extract_text() or "") for p in reader.pages)
            return {"kind": "document", "text": text[:MAX_EXTRACT_CHARS], "note": f"{len(reader.pages)} PDF pages"}
        if ext == ".docx":
            import docx
            d = docx.Document(io.BytesIO(data))
            parts = [p.text for p in d.paragraphs]
            for table in d.tables:
                for row in table.rows:
                    parts.append(" | ".join(c.text for c in row.cells))
            # headers/footers are a classic hiding place for injected text
            for s in d.sections:
                parts += [p.text for p in s.header.paragraphs] + [p.text for p in s.footer.paragraphs]
            text = "\n".join(t for t in parts if t)
            return {"kind": "document", "text": text[:MAX_EXTRACT_CHARS], "note": "Word document"}
        if ext in TEXT_EXT or _looks_text(data):
            return {"kind": "text", "text": data.decode("utf-8", errors="replace")[:MAX_EXTRACT_CHARS], "note": "text"}
    except Exception as e:
        return {"kind": "binary", "text": "", "note": f"could not extract text: {e.__class__.__name__}"}
    return {"kind": "binary", "text": "", "note": "no extractable text"}


def _looks_text(data: bytes) -> bool:
    sample = data[:4096]
    if not sample or b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


# =============================================================================
# AI Guard
# =============================================================================

def _payload(text: str) -> bytes:
    return json.dumps({"guard": text}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def chunk_text(text: str, max_bytes: int, overlap: int = 400) -> list:
    """Split text so each AI Guard request body stays under max_bytes (measured on
    the exact JSON we send, so escaping and multi-byte characters are counted).
    Prefers to cut on a paragraph / line / word boundary; consecutive chunks
    overlap by `overlap` characters."""
    if len(_payload(text)) <= max_bytes:
        return [text]
    chunks, start, n = [], 0, len(text)
    while start < n:
        end = min(n, start + max_bytes)
        while end > start + 1 and len(_payload(text[start:end])) > max_bytes:
            end = start + max(1, int((end - start) * 0.9))
        if end < n:
            floor = start + int((end - start) * 0.75)
            for sep in ("\n\n", "\n", ". ", " "):
                cut = text.rfind(sep, floor, end)
                if cut > start:
                    end = cut + len(sep)
                    break
        chunks.append(text[start:end])
        if end >= n:
            break
        start = max(end - overlap, start + 1)
    return chunks


async def _guard_call(cfg: dict, text: str) -> dict:
    key = hashlib.sha256((cfg["url"] + "\0" + text).encode("utf-8", "replace")).hexdigest()
    if key in _CACHE:
        _CACHE.move_to_end(key)
        return {**_CACHE[key], "cached": True}
    async with _SEM:
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.post(cfg["url"].rstrip("/"), content=_payload(text),
                                 params={"detailedResponse": "false"},
                                 headers={"Authorization": f"Bearer {cfg['key']}",
                                          "Content-Type": "application/json",
                                          "TMV1-Application-Name": "ai-target-range"})
            if r.status_code >= 400:
                return {"verdict": "error", "reason": f"HTTP {r.status_code}: {r.text[:200]}"}
            res = r.json()
        except Exception as e:
            return {"verdict": "error", "reason": f"{e.__class__.__name__}: {e}"}
    decision = str(res.get("action") or res.get("decision") or res.get("recommendation") or "allow").lower()
    reasons = res.get("reasons") or res.get("reason") or []
    if isinstance(reasons, str):
        reasons = [reasons]
    out = {"verdict": "block" if decision == "block" else "allow", "reason": "; ".join(map(str, reasons))[:300]}
    _CACHE[key] = out
    if len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)
    return out


async def ai_guard_scan(cfg: dict, text: str, stage: str) -> dict:
    """Scan arbitrary-length text. cfg = CONFIG['trend']['ai_guard']."""
    t0 = time.time()
    base = {"engine": "ai_guard", "stage": stage}
    if not text or not text.strip():
        return {**base, "verdict": "allow", "chunks": 0, "reason": "empty", "ms": 0}
    if not cfg.get("key"):
        return {**base, "verdict": "block" if cfg.get("fail_closed") else "error",
                "reason": "AI Guard API key not configured", "chunks": 0, "ms": 0}
    chunks = chunk_text(text, int(cfg.get("max_bytes") or 48 * 1024))
    cap = int(cfg.get("max_chunks") or 64)
    over = len(chunks) > cap
    results = await asyncio.gather(*(_guard_call(cfg, c) for c in chunks[:cap]))
    blocked = [i for i, r in enumerate(results) if r["verdict"] == "block"]
    errors = [i for i, r in enumerate(results) if r["verdict"] == "error"]
    reasons = sorted({r["reason"] for r in results if r["verdict"] != "allow" and r.get("reason")})
    out = {**base, "chunks": len(chunks), "scanned_chunks": min(len(chunks), cap), "blocked_chunks": blocked,
           "bytes": len(text.encode("utf-8", "replace")), "ms": int((time.time() - t0) * 1000)}
    if blocked:
        return {**out, "verdict": "block", "reason": "; ".join(reasons) or "blocked by AI Guard"}
    if errors:
        verdict = "block" if cfg.get("fail_closed") else "error"
        return {**out, "verdict": verdict, "reason": f"{len(errors)} chunk(s) not inspected: {reasons[0] if reasons else ''}"[:300]}
    if over:
        verdict = "block" if cfg.get("fail_closed") else "partial"
        return {**out, "verdict": verdict,
                "reason": f"content too large: only the first {cap} of {len(chunks)} chunks were inspected"}
    return {**out, "verdict": "allow", "reason": ""}


# =============================================================================
# File Security (malware / PML)
# =============================================================================

async def file_security_scan(cfg: dict, name: str, data: bytes, tags: list) -> dict:
    """cfg = CONFIG['trend']['file_security']."""
    t0 = time.time()
    base = {"engine": "file_security", "stage": "file", "bytes": len(data)}
    fail = "block" if cfg.get("fail_closed", True) else "error"
    if not V1FS_AVAILABLE:
        return {**base, "verdict": fail, "reason": "File Security SDK not installed", "ms": 0}
    if not cfg.get("key"):
        return {**base, "verdict": fail, "reason": "File Security API key not configured", "ms": 0}
    handle = None
    try:
        handle = amaas_aio.init_by_region(region=cfg.get("region") or "us-east-1", api_key=cfg["key"])
        raw = await asyncio.wait_for(
            amaas_aio.scan_buffer(handle, data, name, tags=[t[:63] for t in tags][:8], pml=bool(cfg.get("pml"))),
            timeout=90)
        res = json.loads(raw)
    except Exception as e:
        return {**base, "verdict": fail, "reason": f"scan failed: {e.__class__.__name__}: {str(e)[:200]}",
                "ms": int((time.time() - t0) * 1000)}
    finally:
        if handle is not None:
            try:
                await amaas_aio.quit(handle)
            except Exception:
                pass
    found = res.get("foundMalwares") or []
    names = sorted({m.get("malwareName", "?") for m in found})
    malicious = bool(found) or int(res.get("scanResult") or 0) > 0
    return {**base, "verdict": "block" if malicious else "allow",
            "reason": ("malware: " + ", ".join(names)) if malicious else "",
            "scan_id": res.get("scanId"), "sha256": res.get("fileSHA256"),
            "ms": int((time.time() - t0) * 1000)}


def summarize(checks: list) -> dict:
    """Combine engine results → {'blocked': bool, 'by': [...], 'reason': str}."""
    blk = [c for c in checks if c and c.get("verdict") == "block"]
    return {"blocked": bool(blk), "by": [f"{c['engine']}:{c['stage']}" for c in blk],
            "reason": "; ".join(f"{'AI Guard' if c['engine'] == 'ai_guard' else 'File Security'} ({c['stage']}): "
                                f"{c.get('reason') or 'blocked'}" for c in blk)}
