"""
API Compliance Fixer — FastAPI Backend v4 (Trial Mode)
No payment gateway — free trial with feedback collection.
Supports: Postman v2/v2.1 collections + OpenAPI 3.x specs
Frameworks: SAMA, PCI-DSS, NIS2, GDPR, DORA
"""
from __future__ import annotations

import csv
import io
import json
import os
import secrets
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from frameworks import FRAMEWORK_META, FRAMEWORK_RULES
from transform import detect_format, preview, transform

# ── Config ─────────────────────────────────────────────────────────────────────
BASE_URL         = os.getenv("BASE_URL", "http://localhost:8000")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
VALID_FRAMEWORKS = set(FRAMEWORK_META.keys())
FEEDBACK_FILE    = Path(os.getenv("FEEDBACK_FILE", "/tmp/feedback.csv"))
ADMIN_KEY        = os.getenv("ADMIN_KEY", "")

# ── In-memory stores ────────────────────────────────────────────────────────────
pending_uploads: dict[str, dict] = {}   # upload_token  → entry
trial_tokens:    dict[str, dict] = {}   # download_token → entry

# ── App setup ───────────────────────────────────────────────────────────────────
app = FastAPI(title="API Compliance Fixer — Trial", version="4.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

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

def _fw_label(entry: dict) -> str:
    return " + ".join(FRAMEWORK_META[f]["name"] for f in entry["frameworks"] if f in FRAMEWORK_META)

def _write_feedback(row: dict) -> None:
    fieldnames = [
        "timestamp", "name", "email", "company", "role",
        "how_heard", "use_case", "collection_name",
        "frameworks", "total_changes", "format",
    ]
    exists = FEEDBACK_FILE.exists()
    with open(FEEDBACK_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        if not exists:
            writer.writeheader()
        writer.writerow(row)

def _count_submissions() -> int:
    try:
        if not FEEDBACK_FILE.exists():
            return 0
        with open(FEEDBACK_FILE, encoding="utf-8") as f:
            return max(0, sum(1 for _ in f) - 1)
    except Exception:
        return -1


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
        "status": "ok", "version": "4.0.0", "mode": "trial",
        "frameworks": list(FRAMEWORK_META.keys()),
        "submissions": _count_submissions(),
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
    pending_uploads[token] = {"raw": raw, "filename": filename, "frameworks": fw_ids, "format": fmt, "changelog": changelog}
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
    """Exchange upload token for download token. Collects user info. No payment."""
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
    _write_feedback({
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "name":           name,
        "email":          email,
        "company":        company.strip(),
        "role":           role.strip(),
        "how_heard":      how_heard,
        "use_case":       use_case,
        "collection_name": _col_name(entry),
        "frameworks":     ", ".join(entry["frameworks"]),
        "total_changes":  changelog.get("total_changes", 0),
        "format":         entry.get("format", ""),
    })

    dl_token = secrets.token_urlsafe(32)
    trial_tokens[dl_token] = entry
    return {"download_token": dl_token, "message": "Access granted — your download is ready."}


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — POST-DOWNLOAD FEEDBACK
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/feedback")
async def submit_feedback(request: Request):
    """Accept star rating + open-text feedback after download."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body.")
    _write_feedback({
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "name":       body.get("name", ""),
        "email":      body.get("email", ""),
        "company":    "", "role":    "", "how_heard": "",
        "use_case":   body.get("comment", ""),
        "collection_name": "",
        "frameworks": "",
        "total_changes": "",
        "format": f"post-download | rating={body.get('rating','')} | would_pay={body.get('would_pay','')} | price={body.get('price_expectation','')}",
    })
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — ADMIN
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/admin/feedback")
async def export_feedback(key: str = ""):
    """Download the full feedback CSV. Set ADMIN_KEY env var to protect."""
    if ADMIN_KEY and key != ADMIN_KEY:
        raise HTTPException(403, "Invalid admin key.")
    if not FEEDBACK_FILE.exists():
        raise HTTPException(404, "No feedback collected yet.")
    content = FEEDBACK_FILE.read_text(encoding="utf-8")
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=feedback.csv"},
    )


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
        raise HTTPException(422, f"Could not parse stored file: {exc}") from exc
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
