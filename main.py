"""
API Compliance Fixer — FastAPI Backend v5
Feedback via Google Forms (server-side POST — no API key, no OAuth).
Supports: Postman v2/v2.1 + OpenAPI 3.x | Frameworks: SAMA, PCI-DSS, NIS2, GDPR, DORA
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
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
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

# ── Google Forms ───────────────────────────────────────────────────────────────
# Set these from your form's pre-fill URL (see README for instructions).
# GFORM_URL  : https://docs.google.com/forms/d/<FORM_ID>/formResponse
# GFORM_* entry IDs : the entry.XXXXXXXXXX= values from the pre-fill URL
GFORM_URL          = os.getenv("GFORM_URL", "")
GFORM_NAME         = os.getenv("GFORM_NAME",         "entry.000000001")
GFORM_EMAIL        = os.getenv("GFORM_EMAIL",        "entry.000000002")
GFORM_COMPANY      = os.getenv("GFORM_COMPANY",      "entry.000000003")
GFORM_ROLE         = os.getenv("GFORM_ROLE",         "entry.000000004")
GFORM_HOW_HEARD    = os.getenv("GFORM_HOW_HEARD",    "entry.000000005")
GFORM_USE_CASE     = os.getenv("GFORM_USE_CASE",     "entry.000000006")
GFORM_COLLECTION   = os.getenv("GFORM_COLLECTION",   "entry.000000007")
GFORM_FRAMEWORKS   = os.getenv("GFORM_FRAMEWORKS",   "entry.000000008")
GFORM_CHANGES      = os.getenv("GFORM_CHANGES",      "entry.000000009")
GFORM_FORMAT       = os.getenv("GFORM_FORMAT",       "entry.000000010")
GFORM_TIMESTAMP    = os.getenv("GFORM_TIMESTAMP",    "entry.000000011")

# ── In-memory stores ───────────────────────────────────────────────────────────
pending_uploads: dict[str, dict] = {}
trial_tokens:    dict[str, dict] = {}

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="API Compliance Fixer — Trial", version="5.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ═══════════════════════════════════════════════════════════════════════════════
# GOOGLE FORMS HELPER
# ═══════════════════════════════════════════════════════════════════════════════

async def _submit_to_gform(data: dict) -> bool:
    """
    POST a submission to the Google Form.
    Returns True on success, False if GFORM_URL is not configured.
    Never raises — a Forms failure must not block the download.
    """
    if not GFORM_URL:
        # Not configured — log to stdout so it still shows in Railway logs
        print(f"[GFORM] Not configured. Submission data: {json.dumps(data)}")
        return False

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

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.post(
                GFORM_URL,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=8,
            )
        # Google Forms returns 200 on success and redirects on completion —
        # both are fine. Anything else we log but don't raise.
        if resp.status_code not in (200, 201, 302):
            print(f"[GFORM] Unexpected status {resp.status_code}")
        return True
    except Exception as exc:
        print(f"[GFORM] Submission error: {exc}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# FILE HELPERS
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

def _fw_label(entry: dict) -> str:
    return " + ".join(FRAMEWORK_META[f]["name"] for f in entry["frameworks"] if f in FRAMEWORK_META)


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — STATIC
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse((static_dir / "index.html").read_text(encoding="utf-8"))

@app.get("/api/frameworks")
async def list_frameworks():
    return [
        {**meta, "rule_count": len(FRAMEWORK_RULES.get(fid, [])),
         "rules": [{"id": r.id, "title": r.title, "severity": r.severity, "reference": r.reference}
                   for r in FRAMEWORK_RULES.get(fid, [])]}
        for fid, meta in FRAMEWORK_META.items()
    ]

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "5.0.0",
        "mode": "trial",
        "gform_configured": bool(GFORM_URL),
        "frameworks": list(FRAMEWORK_META.keys()),
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
    fw_ids = _parse_frameworks(frameworks)
    parsed = _parse_file(raw, filename)
    try:
        fmt = detect_format(parsed)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    changelog = preview(parsed, fw_ids)
    token = secrets.token_urlsafe(32)
    pending_uploads[token] = {
        "raw": raw, "filename": filename,
        "frameworks": fw_ids, "format": fmt, "changelog": changelog,
    }
    return {"upload_token": token, "format": fmt, "changelog_preview": changelog}


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — TRIAL ACCESS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/trial")
async def request_trial(
    upload_token: str = Form(...),
    name:         str = Form(...),
    email:        str = Form(...),
    company:      str = Form(""),
    role:         str = Form(""),
    how_heard:    str = Form(""),
    use_case:     str = Form(""),
):
    """
    Validate the form, submit to Google Forms, issue download token.
    The Google Forms submission is fire-and-forget — it never blocks the download.
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

    changelog = entry.get("changelog", {})

    # Fire-and-forget to Google Forms — does NOT block on failure
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

    dl_token = secrets.token_urlsafe(32)
    trial_tokens[dl_token] = entry
    return {"download_token": dl_token, "message": "Access granted — your download is ready."}


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — POST-DOWNLOAD FEEDBACK
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/feedback")
async def submit_feedback(request: Request):
    """Post-download star rating + open comment — also goes to Google Forms."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body.")

    await _submit_to_gform({
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "name":            body.get("name", ""),
        "email":           body.get("email", ""),
        "company":         "",
        "role":            "",
        "how_heard":       "",
        "use_case":        body.get("comment", ""),
        "collection_name": "",
        "frameworks":      "",
        "total_changes":   "",
        "format":          (
            f"post-download | rating={body.get('rating','')} | "
            f"would_pay={body.get('would_pay','')} | "
            f"price={body.get('price_expectation','')}"
        ),
    })
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — DOWNLOAD
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/download/{download_token}")
async def download(download_token: str):
    entry = trial_tokens.pop(download_token, None)
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
        zf.writestr(f"{out_name}.json",           json.dumps(fixed, indent=2, ensure_ascii=False))
        zf.writestr(f"{out_name}_changelog.json", json.dumps(changelog, indent=2, ensure_ascii=False))
        zf.writestr(f"{out_name}_summary.md",     _build_md(changelog))
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{out_name}.zip"'})


def _build_md(cl: dict) -> str:
    lines = ["# API Compliance Fix Summary", "",
             f"**Tool:** {cl.get('tool')} v{cl.get('version')}",
             f"**Generated:** {cl.get('generated_at')}",
             f"**Collection:** {cl.get('collection_name')}",
             f"**Frameworks:** {', '.join(cl.get('frameworks', []))}",
             f"**Total changes:** {cl.get('total_changes', 0)}", "",
             "## Severity Breakdown", ""]
    sev = cl.get("severity_summary", {})
    for s in ("critical", "high", "medium", "info"):
        lines.append(f"- **{s.capitalize()}:** {sev.get(s, 0)}")
    lines += ["", "## Changes by Rule", ""]
    for rule in cl.get("changes_by_rule", []):
        lines.append(f"### [{rule['rule_id']}] {rule['rule_title']}")
        lines.append(f"*{rule.get('reference', '')}* · Severity: **{rule.get('severity', '')}**\n")
        for req in rule.get("affected_requests", []):
            lines.append(f"- `{req['request']}` — {req['detail']}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
