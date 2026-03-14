"""
API Compliance Fixer — FastAPI Backend v8
Flow:
  1. Upload file → redacted preview (2 rules shown, rest locked)
  2. Submit feedback form → Google Forms logged → full results + download unlocked
  No tokens, no email, no admin page.
"""
from __future__ import annotations

import io
import json
import os
import secrets
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from frameworks import FRAMEWORK_META, FRAMEWORK_RULES
from transform import detect_format, preview, transform

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

BASE_URL         = os.getenv("BASE_URL", "http://localhost:8000")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
VALID_FRAMEWORKS = set(FRAMEWORK_META.keys())

# Google Forms
GFORM_URL        = os.getenv("GFORM_URL", "")
GFORM_NAME       = os.getenv("GFORM_NAME",       "entry.000000001")
GFORM_EMAIL      = os.getenv("GFORM_EMAIL",      "entry.000000002")
GFORM_COMPANY    = os.getenv("GFORM_COMPANY",    "entry.000000003")
GFORM_ROLE       = os.getenv("GFORM_ROLE",       "entry.000000004")
GFORM_HOW_HEARD  = os.getenv("GFORM_HOW_HEARD",  "entry.000000005")
GFORM_USE_CASE   = os.getenv("GFORM_USE_CASE",   "entry.000000006")
GFORM_COLLECTION = os.getenv("GFORM_COLLECTION", "entry.000000007")
GFORM_FRAMEWORKS = os.getenv("GFORM_FRAMEWORKS", "entry.000000008")
GFORM_CHANGES    = os.getenv("GFORM_CHANGES",    "entry.000000009")
GFORM_FORMAT     = os.getenv("GFORM_FORMAT",     "entry.000000010")
GFORM_TIMESTAMP  = os.getenv("GFORM_TIMESTAMP",  "entry.000000011")

# ── In-memory stores ───────────────────────────────────────────────────────────
# upload_token  → { raw, filename, frameworks, format, changelog }
pending_uploads: dict[str, dict] = {}
# download_token → { raw, filename, frameworks, format }
# Single-use. Issued immediately on form submission.
download_tokens: dict[str, dict] = {}

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="API Compliance Fixer", version="8.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_frameworks(s: str) -> list[str]:
    ids = [f.strip().upper() for f in s.split(",") if f.strip()]
    bad = [f for f in ids if f not in VALID_FRAMEWORKS]
    if bad:
        raise HTTPException(400, f"Unknown frameworks: {', '.join(bad)}.")
    if not ids:
        raise HTTPException(400, "At least one framework must be selected.")
    return list(dict.fromkeys(ids))

def _try_yaml(raw: bytes) -> dict:
    try:
        import yaml
        return yaml.safe_load(raw)
    except Exception:
        raise HTTPException(422, "File is not valid JSON or YAML.")

def _parse_file(raw: bytes, filename: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        if filename.endswith((".yaml", ".yml")):
            return _try_yaml(raw)
        raise HTTPException(422, "Invalid JSON. Use .yaml/.yml for YAML files.")

def _col_name(entry: dict) -> str:
    try:
        d = json.loads(entry["raw"])
        key = "name" if entry["format"] == "postman" else "title"
        return d.get("info", {}).get(key, "API File")
    except Exception:
        return "API File"

def _redact_changelog(changelog: dict, preview_rules: int = 2) -> dict:
    rules = changelog.get("changes_by_rule", [])
    return {
        **changelog,
        "changes_by_rule": rules[:preview_rules],
        "hidden_rules":    max(0, len(rules) - preview_rules),
        "redacted":        True,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# GOOGLE FORMS
# ═══════════════════════════════════════════════════════════════════════════════

async def _submit_to_gform(data: dict) -> None:
    """Fire-and-forget. Logs every step so Railway logs show exactly what happened."""
    if not GFORM_URL:
        print(f"[GFORM] GFORM_URL not set — skipping. Data: {json.dumps(data)}")
        return

    payload = {
        GFORM_NAME:       data.get("name", ""),
        GFORM_EMAIL:      data.get("email", ""),
        GFORM_COMPANY:    data.get("company", ""),
        GFORM_ROLE:       data.get("role", ""),
        GFORM_HOW_HEARD:  data.get("how_heard", ""),
        GFORM_USE_CASE:   data.get("use_case", ""),
        GFORM_COLLECTION: data.get("collection_name", ""),
        GFORM_FRAMEWORKS: data.get("frameworks", ""),
        GFORM_CHANGES:    str(data.get("total_changes", "")),
        GFORM_FORMAT:     data.get("format", ""),
        GFORM_TIMESTAMP:  data.get("timestamp", ""),
    }

    print(f"[GFORM] Submitting to: {GFORM_URL}")
    print(f"[GFORM] Payload keys: {list(payload.keys())}")
    print(f"[GFORM] First entry key value: {list(payload.items())[0]}")

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            r = await client.post(
                GFORM_URL,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=8,
            )
        print(f"[GFORM] Response status: {r.status_code}")
        print(f"[GFORM] Final URL: {r.url}")
        if r.status_code not in (200, 201, 302):
            print(f"[GFORM] Unexpected status — body snippet: {r.text[:300]}")
        else:
            print(f"[GFORM] Success ✓")
    except Exception as exc:
        print(f"[GFORM] Exception: {type(exc).__name__}: {exc}")


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse((static_dir / "index.html").read_text(encoding="utf-8"))


@app.get("/api/frameworks")
async def list_frameworks():
    return [
        {
            **meta,
            "rule_count": len(FRAMEWORK_RULES.get(fid, [])),
            "rules": [
                {"id": r.id, "title": r.title,
                 "severity": r.severity, "reference": r.reference}
                for r in FRAMEWORK_RULES.get(fid, [])
            ],
        }
        for fid, meta in FRAMEWORK_META.items()
    ]


@app.get("/api/health")
async def health():
    return {
        "status":           "ok",
        "version":          "8.0.0",
        "mode":             "form-gated trial",
        "gform_configured": bool(GFORM_URL),
        "frameworks":       list(FRAMEWORK_META.keys()),
    }


@app.get("/api/debug/gform")
async def debug_gform():
    """
    Shows loaded env vars and fires a live test submission to Google Forms.
    Remove this endpoint once the integration is confirmed working.
    """
    # Show what env vars actually loaded (mask the URL slightly for safety)
    url_display = GFORM_URL[:60] + "…" if len(GFORM_URL) > 60 else GFORM_URL

    config = {
        "GFORM_URL":        url_display or "NOT SET",
        "GFORM_NAME":       GFORM_NAME,
        "GFORM_EMAIL":      GFORM_EMAIL,
        "GFORM_COMPANY":    GFORM_COMPANY,
        "GFORM_ROLE":       GFORM_ROLE,
        "GFORM_HOW_HEARD":  GFORM_HOW_HEARD,
        "GFORM_USE_CASE":   GFORM_USE_CASE,
        "GFORM_COLLECTION": GFORM_COLLECTION,
        "GFORM_FRAMEWORKS": GFORM_FRAMEWORKS,
        "GFORM_CHANGES":    GFORM_CHANGES,
        "GFORM_FORMAT":     GFORM_FORMAT,
        "GFORM_TIMESTAMP":  GFORM_TIMESTAMP,
    }

    # Check for placeholder values
    placeholders = [k for k, v in config.items()
                    if v.startswith("entry.0000") or v == "NOT SET"]

    # Fire a live test submission
    test_result = "skipped — GFORM_URL not set"
    if GFORM_URL:
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                r = await client.post(
                    GFORM_URL,
                    data={
                        GFORM_NAME:       "DEBUG TEST",
                        GFORM_EMAIL:      "debug@test.com",
                        GFORM_COMPANY:    "Debug",
                        GFORM_ROLE:       "Test",
                        GFORM_HOW_HEARD:  "other",
                        GFORM_USE_CASE:   "debug endpoint test",
                        GFORM_COLLECTION: "debug_collection",
                        GFORM_FRAMEWORKS: "DEBUG",
                        GFORM_CHANGES:    "0",
                        GFORM_FORMAT:     "debug",
                        GFORM_TIMESTAMP:  datetime.now(timezone.utc).isoformat(),
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=10,
                )
            test_result = {
                "status_code":  r.status_code,
                "final_url":    str(r.url),
                "redirect_chain": [h.status_code for h in r.history],
                "success":      r.status_code in (200, 201, 302),
            }
        except Exception as exc:
            test_result = f"ERROR: {type(exc).__name__}: {exc}"

    return {
        "env_vars_loaded":   config,
        "placeholder_vars":  placeholders,
        "placeholder_warning": (
            f"{len(placeholders)} var(s) still have placeholder values — "
            "these will POST to Google but be silently ignored"
            if placeholders else "none — all vars look real"
        ),
        "live_test_result":  test_result,
        "note": "Delete this endpoint once confirmed working",
    }


@app.post("/api/upload")
async def upload(file: UploadFile = File(...), frameworks: str = Form(...)):
    """Accept file, return redacted preview + upload token."""
    filename = file.filename or ""
    if not filename.endswith((".json", ".yaml", ".yml")):
        raise HTTPException(400, "Only .json, .yaml, or .yml files are accepted.")
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File exceeds 10 MB limit.")
    fw_ids  = _parse_frameworks(frameworks)
    parsed  = _parse_file(raw, filename)
    try:
        fmt = detect_format(parsed)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    full_changelog = preview(parsed, fw_ids)
    token = secrets.token_urlsafe(32)
    pending_uploads[token] = {
        "raw": raw, "filename": filename,
        "frameworks": fw_ids, "format": fmt,
        "changelog": full_changelog,
    }
    return {
        "upload_token":      token,
        "format":            fmt,
        "changelog_preview": _redact_changelog(full_changelog, preview_rules=2),
    }


@app.post("/api/unlock")
async def unlock(
    upload_token: str = Form(...),
    name:         str = Form(...),
    email:        str = Form(...),
    company:      str = Form(""),
    role:         str = Form(""),
    how_heard:    str = Form(""),
    use_case:     str = Form(""),
):
    """
    Validate form, log to Google Forms, return full changelog + download token.
    This is the only gate — no access token, no admin step.
    """
    entry = pending_uploads.get(upload_token)
    if not entry:
        raise HTTPException(404, "Upload not found or expired. Please re-upload your file.")

    name  = name.strip()
    email = email.strip().lower()
    if not name:
        raise HTTPException(400, "Name is required.")
    if not email or "@" not in email:
        raise HTTPException(400, "A valid email address is required.")

    changelog = entry["changelog"]

    # Log to Google Forms — fire and forget
    await _submit_to_gform({
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "name":            name,
        "email":           email,
        "company":         company.strip(),
        "role":            role.strip(),
        "how_heard":       how_heard,
        "use_case":        use_case,
        "collection_name": _col_name(entry),
        "frameworks":      ", ".join(entry["frameworks"]),
        "total_changes":   changelog.get("total_changes", 0),
        "format":          entry.get("format", ""),
    })

    # Issue single-use download token
    dl_token = secrets.token_urlsafe(32)
    download_tokens[dl_token] = entry

    return {
        "ok":             True,
        "download_token": dl_token,
        "changelog":      changelog,   # full, unredacted
    }


@app.get("/api/download/{download_token}")
async def download(download_token: str):
    """Transform and stream the fixed ZIP. One-time use."""
    entry = download_tokens.pop(download_token, None)
    if not entry:
        raise HTTPException(404, "Download token not found or already used.")
    raw_bytes     = entry["raw"]
    framework_ids = entry["frameworks"]
    filename      = entry.get("filename", "collection.json")
    try:
        parsed = _parse_file(raw_bytes, filename)
    except Exception as exc:
        raise HTTPException(422, f"Could not parse file: {exc}") from exc
    fixed, changelog = transform(parsed, framework_ids)
    stem     = filename.rsplit(".", 1)[0]
    fw_sfx   = "_".join(f.lower() for f in framework_ids)
    out_name = f"{stem}_compliant_{fw_sfx}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{out_name}.json",
                    json.dumps(fixed, indent=2, ensure_ascii=False))
        zf.writestr(f"{out_name}_changelog.json",
                    json.dumps(changelog, indent=2, ensure_ascii=False))
        zf.writestr(f"{out_name}_summary.md", _build_md(changelog))
    buf.seek(0)
    return StreamingResponse(
        buf, media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{out_name}.zip"'},
    )


def _build_md(cl: dict) -> str:
    lines = [
        "# API Compliance Fix Summary", "",
        f"**Tool:** {cl.get('tool')} v{cl.get('version')}",
        f"**Generated:** {cl.get('generated_at')}",
        f"**Collection:** {cl.get('collection_name')}",
        f"**Frameworks:** {', '.join(cl.get('frameworks', []))}",
        f"**Total changes:** {cl.get('total_changes', 0)}", "",
        "## Severity Breakdown", "",
    ]
    sev = cl.get("severity_summary", {})
    for s in ("critical", "high", "medium", "info"):
        lines.append(f"- **{s.capitalize()}:** {sev.get(s, 0)}")
    lines += ["", "## Changes by Rule", ""]
    for rule in cl.get("changes_by_rule", []):
        lines.append(f"### [{rule['rule_id']}] {rule['rule_title']}")
        lines.append(
            f"*{rule.get('reference', '')}* · Severity: **{rule.get('severity', '')}**\n"
        )
        for req in rule.get("affected_requests", []):
            lines.append(f"- `{req['request']}` — {req['detail']}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
