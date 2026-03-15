"""
API Compliance Fixer — FastAPI Backend v9
Flow:
  1. Upload → redacted preview
  2a. Request access: browser generates token → POST /api/request-access
      → sha256(token) stored + submitted to Google Form (with token)
      → team sends token to user manually
  2b. Redeem: user pastes token → POST /api/redeem
      → sha256 compared → full changelog + download token issued
  3. Support: POST /api/support → Google support form
"""
from __future__ import annotations

import hashlib
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

# ── Access request form ────────────────────────────────────────────────────────
GFORM_URL        = os.getenv("GFORM_URL", "")
GFORM_NAME       = os.getenv("GFORM_NAME",       "entry.1810443692")
GFORM_EMAIL      = os.getenv("GFORM_EMAIL",      "entry.1282272068")
GFORM_COMPANY    = os.getenv("GFORM_COMPANY",    "entry.2083451802")
GFORM_ROLE       = os.getenv("GFORM_ROLE",       "entry.1171016044")
GFORM_HOW_HEARD  = os.getenv("GFORM_HOW_HEARD",  "entry.518972485")
GFORM_USE_CASE   = os.getenv("GFORM_USE_CASE",   "entry.1483517663")
GFORM_COLLECTION = os.getenv("GFORM_COLLECTION", "entry.733773756")
GFORM_FRAMEWORKS = os.getenv("GFORM_FRAMEWORKS", "entry.902499515")
GFORM_CHANGES    = os.getenv("GFORM_CHANGES",    "entry.1152321901")
GFORM_FORMAT     = os.getenv("GFORM_FORMAT",     "entry.1848111736")
GFORM_TIMESTAMP  = os.getenv("GFORM_TIMESTAMP",  "entry.47021805")
GFORM_TOKEN      = os.getenv("GFORM_TOKEN",      "entry.1662570945")

# ── Support form ───────────────────────────────────────────────────────────────
GFORM_SUPPORT_URL   = os.getenv("GFORM_SUPPORT_URL",   "")
GFORM_SUPPORT_EMAIL = os.getenv("GFORM_SUPPORT_EMAIL", "entry.568404855")
GFORM_SUPPORT_QUERY = os.getenv("GFORM_SUPPORT_QUERY", "entry.584910034")

# ── In-memory stores ───────────────────────────────────────────────────────────
# upload_token  → { raw, filename, frameworks, format, changelog }
pending_uploads: dict[str, dict] = {}

# token_hash → { email, name, created_at, use_count }
# sha256(raw_token) stored — raw token never held server-side
access_hashes: dict[str, dict] = {}

# download_token → entry  (single-use)
download_tokens: dict[str, dict] = {}

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="API Compliance Fixer", version="9.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.strip().encode()).hexdigest()

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
# GOOGLE FORMS HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _build_how_heard_fields(how_heard_raw: str, entry_key: str) -> dict:
    """
    Map a how_heard value to the correct Google Forms field(s).
    Handles the __other_option__ mechanism for Twitter/X and Other.
    """
    HOW_HEARD_MAP = {
        "linkedin":  "LinkedIn",
        "colleague": "Colleague / referral",
        "github":    "GitHub",
        "search":    "Web search",
    }
    how = how_heard_raw.strip().lower()
    if how in HOW_HEARD_MAP:
        return {entry_key: HOW_HEARD_MAP[how]}
    elif how:
        label = {"twitter": "Twitter / X", "other": "Other"}.get(how, how_heard_raw)
        return {
            entry_key: "__other_option__",
            entry_key + ".other_option_response": label,
        }
    return {}   # blank — omit key entirely


async def _submit_access_form(data: dict) -> None:
    """Submit to the access request Google Form. Fire-and-forget."""
    if not GFORM_URL:
        print(f"[GFORM] Not configured. Data: {json.dumps({k:v for k,v in data.items() if k != 'token'})}")
        return

    payload: dict[str, str] = {
        GFORM_NAME:       data.get("name", ""),
        GFORM_EMAIL:      data.get("email", ""),
        GFORM_COMPANY:    data.get("company", ""),
        GFORM_ROLE:       data.get("role", ""),
        GFORM_USE_CASE:   data.get("use_case", ""),
        GFORM_COLLECTION: data.get("collection_name", ""),
        GFORM_FRAMEWORKS: data.get("frameworks", ""),
        GFORM_CHANGES:    str(data.get("total_changes", "")),
        GFORM_FORMAT:     data.get("format", ""),
        GFORM_TIMESTAMP:  data.get("timestamp", ""),
        GFORM_TOKEN:      data.get("token", ""),
    }
    payload.update(_build_how_heard_fields(data.get("how_heard", ""), GFORM_HOW_HEARD))

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            r = await client.post(
                GFORM_URL, data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=8,
            )
        if r.status_code not in (200, 201, 302):
            print(f"[GFORM] Unexpected status {r.status_code}")
        else:
            print(f"[GFORM] Access request submitted for {data.get('email','?')}")
    except Exception as exc:
        print(f"[GFORM] Error: {type(exc).__name__}: {exc}")


async def _submit_support_form(email: str, query: str) -> None:
    """Submit to the support Google Form. Fire-and-forget."""
    if not GFORM_SUPPORT_URL:
        print(f"[SUPPORT] Not configured. email={email}")
        return
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            r = await client.post(
                GFORM_SUPPORT_URL,
                data={
                    GFORM_SUPPORT_EMAIL: email,
                    GFORM_SUPPORT_QUERY: query,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=8,
            )
        if r.status_code not in (200, 201, 302):
            print(f"[SUPPORT] Unexpected status {r.status_code}")
        else:
            print(f"[SUPPORT] Query submitted from {email}")
    except Exception as exc:
        print(f"[SUPPORT] Error: {type(exc).__name__}: {exc}")


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — STATIC
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
        "status":              "ok",
        "version":             "9.0.0",
        "mode":                "token-gated trial",
        "gform_configured":    bool(GFORM_URL),
        "support_configured":  bool(GFORM_SUPPORT_URL),
        "active_tokens":       len(access_hashes),
        "frameworks":          list(FRAMEWORK_META.keys()),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — UPLOAD
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/upload")
async def upload(file: UploadFile = File(...), frameworks: str = Form(...)):
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


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — REQUEST ACCESS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/request-access")
async def request_access(
    upload_token: str = Form(...),
    name:         str = Form(...),
    email:        str = Form(...),
    company:      str = Form(""),
    role:         str = Form(""),
    how_heard:    str = Form(""),
    use_case:     str = Form(""),
    access_token: str = Form(...),   # generated by browser, sent here + to Google
):
    """
    Register sha256(access_token) and submit to Google Form.
    The raw token is never stored — only the hash.
    Team sees the raw token in Google Sheet and sends it to the user.
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
    if not access_token or len(access_token) < 8:
        raise HTTPException(400, "Invalid access token — please refresh and try again.")

    # Store the hash — raw token never persisted
    token_hash = _hash_token(access_token)
    access_hashes[token_hash] = {
        "email":      email,
        "name":       name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "use_count":  0,
    }

    changelog = entry["changelog"]

    # Submit to Google Form — includes the raw token so team can send it
    await _submit_access_form({
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
        "token":           access_token,   # raw — goes to Sheet for team to send
    })

    return {
        "ok":      True,
        "message": "Request received. Our team will review and send your access token shortly.",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — REDEEM TOKEN
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/redeem")
async def redeem_token(
    access_token: str = Form(...),
    upload_token: str = Form(...),
):
    """
    Hash the submitted token and compare against stored hashes.
    No plaintext comparison — raw tokens never leave the client or the Sheet.
    """
    token_hash = _hash_token(access_token)

    hash_entry = access_hashes.get(token_hash)
    if not hash_entry:
        raise HTTPException(
            404,
            "Invalid or unrecognised access token. "
            "Check for typos or request a new token.",
        )

    upload_entry = pending_uploads.get(upload_token)
    if not upload_entry:
        raise HTTPException(
            410,
            "Your file session has expired — please re-upload your file and try again.",
        )

    # Track usage
    hash_entry["use_count"] += 1
    hash_entry["last_used"]  = datetime.now(timezone.utc).isoformat()

    # Issue fresh single-use download token
    dl_token = secrets.token_urlsafe(32)
    download_tokens[dl_token] = upload_entry

    return {
        "ok":             True,
        "download_token": dl_token,
        "changelog":      upload_entry["changelog"],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — SUPPORT
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/support")
async def support(
    email: str = Form(...),
    query: str = Form(...),
):
    """Submit a support query to the support Google Form."""
    email = email.strip().lower()
    query = query.strip()
    if not email or "@" not in email:
        raise HTTPException(400, "A valid email address is required.")
    if not query:
        raise HTTPException(400, "Query cannot be empty.")

    await _submit_support_form(email, query)
    return {"ok": True, "message": "Query submitted. We'll be in touch shortly."}


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — DOWNLOAD
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/download/{download_token}")
async def download(download_token: str):
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
