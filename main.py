"""
API Compliance Fixer — FastAPI Backend v2
Supports: Postman v2/v2.1 collections + OpenAPI 3.x specs
Frameworks: SAMA, PCI-DSS, NIS2, GDPR, DORA
"""
from __future__ import annotations

import io
import json
import os
import secrets
import zipfile
from pathlib import Path
from typing import Annotated

import stripe
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from frameworks import FRAMEWORK_META, FRAMEWORK_RULES
from transform import detect_format, preview, transform

# ── Config ───────────────────────────────────────────────────────────────────
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
PRICE_CENTS = int(os.getenv("PRICE_CENTS", "2900"))

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
VALID_FRAMEWORKS = set(FRAMEWORK_META.keys())

# ── In-memory stores ─────────────────────────────────────────────────────────
# upload_token → {"raw": bytes, "frameworks": list[str], "format": str}
pending_uploads: dict[str, dict] = {}
# download_token → {"raw": bytes, "frameworks": list[str]}
paid_tokens: dict[str, dict] = {}
# stripe_session_id → upload_token
session_map: dict[str, str] = {}

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="API Compliance Fixer", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_frameworks(frameworks_str: str) -> list[str]:
    """Parse comma-separated framework IDs, validate, deduplicate."""
    ids = [f.strip().upper() for f in frameworks_str.split(",") if f.strip()]
    invalid = [f for f in ids if f not in VALID_FRAMEWORKS]
    if invalid:
        raise HTTPException(400, f"Unknown frameworks: {', '.join(invalid)}. Valid: {', '.join(VALID_FRAMEWORKS)}")
    if not ids:
        raise HTTPException(400, "At least one framework must be selected.")
    return list(dict.fromkeys(ids))  # deduplicate, preserve order


def _try_yaml(raw: bytes) -> dict:
    """Attempt YAML parse (for OpenAPI YAML files)."""
    try:
        import yaml  # type: ignore
        return yaml.safe_load(raw)
    except Exception:
        raise HTTPException(422, "File is not valid JSON or YAML.")


def _parse_file(raw: bytes, filename: str) -> dict:
    """Parse uploaded file as JSON or YAML."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        if filename.endswith((".yaml", ".yml")):
            return _try_yaml(raw)
        raise HTTPException(422, "Invalid JSON. For YAML files use .yaml or .yml extension.")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse((static_dir / "index.html").read_text(encoding="utf-8"))


@app.get("/api/frameworks")
async def list_frameworks():
    """Return metadata for all supported compliance frameworks."""
    result = []
    for fid, meta in FRAMEWORK_META.items():
        rules = FRAMEWORK_RULES.get(fid, [])
        result.append({
            **meta,
            "rule_count": len(rules),
            "rules": [
                {"id": r.id, "title": r.title, "severity": r.severity, "reference": r.reference}
                for r in rules
            ],
        })
    return result


@app.post("/api/upload")
async def upload(
    file: UploadFile = File(...),
    frameworks: str = Form(...),
):
    """
    Upload a Postman collection or OpenAPI spec.
    `frameworks` = comma-separated list e.g. "SAMA,GDPR"
    Returns changelog preview + upload_token.
    """
    filename = file.filename or ""
    if not filename.endswith((".json", ".yaml", ".yml")):
        raise HTTPException(400, "Only .json, .yaml, or .yml files are accepted.")

    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File exceeds 10 MB limit.")

    framework_ids = _parse_frameworks(frameworks)
    parsed = _parse_file(raw, filename)

    try:
        fmt = detect_format(parsed)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    changelog = preview(parsed, framework_ids)

    token = secrets.token_urlsafe(32)
    pending_uploads[token] = {
        "raw": raw,
        "filename": filename,
        "frameworks": framework_ids,
        "format": fmt,
    }

    return {
        "upload_token": token,
        "format": fmt,
        "changelog_preview": changelog,
    }


@app.post("/api/checkout/{upload_token}")
async def create_checkout(upload_token: str):
    """Create Stripe Checkout session for a pending upload."""
    entry = pending_uploads.get(upload_token)
    if not entry:
        raise HTTPException(404, "Upload not found or expired.")

    if not stripe.api_key:
        raise HTTPException(503, "Payment not configured — set STRIPE_SECRET_KEY.")

    frameworks_label = " + ".join(
        FRAMEWORK_META[f]["name"] for f in entry["frameworks"] if f in FRAMEWORK_META
    )

    try:
        raw_dict = json.loads(entry["raw"]) if entry["raw"] else {}
        if entry["format"] == "postman":
            col_name = raw_dict.get("info", {}).get("name", "Collection")
        else:
            col_name = raw_dict.get("info", {}).get("title", "API Spec")
    except Exception:
        col_name = "Your API File"

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": PRICE_CENTS,
                    "product_data": {
                        "name": "API Compliance Fixer",
                        "description": f"{col_name} · {frameworks_label}",
                    },
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=f"{BASE_URL}/api/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}/",
            metadata={"upload_token": upload_token},
        )
    except stripe.StripeError as exc:
        raise HTTPException(502, f"Stripe error: {exc.user_message}") from exc

    session_map[session.id] = upload_token
    return {"checkout_url": session.url}


@app.get("/api/success", response_class=HTMLResponse)
async def payment_success(session_id: str):
    """Verify Stripe payment, issue download token, redirect to app."""
    if not session_id:
        raise HTTPException(400, "Missing session_id.")

    try:
        session = stripe.checkout.Session.retrieve(session_id)
    except stripe.StripeError as exc:
        raise HTTPException(502, str(exc)) from exc

    if session.payment_status != "paid":
        raise HTTPException(402, "Payment not completed.")

    upload_token = session.metadata.get("upload_token") or session_map.get(session_id)
    if not upload_token or upload_token not in pending_uploads:
        raise HTTPException(404, "Upload not found — it may have expired.")

    entry = pending_uploads.pop(upload_token)
    dl_token = secrets.token_urlsafe(32)
    paid_tokens[dl_token] = entry

    return HTMLResponse(
        f"""<!DOCTYPE html><html><head>
        <meta http-equiv="refresh" content="0;url=/?download_token={dl_token}&success=1">
        </head><body>Redirecting…</body></html>"""
    )


@app.post("/api/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    if STRIPE_WEBHOOK_SECRET:
        try:
            stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
        except stripe.SignatureVerificationError:
            raise HTTPException(400, "Invalid webhook signature.")
    return {"ok": True}


@app.get("/api/download/{download_token}")
async def download(download_token: str):
    """Transform file with selected frameworks and stream result as ZIP."""
    entry = paid_tokens.pop(download_token, None)
    if not entry:
        raise HTTPException(404, "Download token not found or already used.")

    raw_bytes: bytes = entry["raw"]
    framework_ids: list[str] = entry["frameworks"]
    filename: str = entry.get("filename", "collection.json")
    fmt: str = entry.get("format", "postman")

    try:
        parsed = _parse_file(raw_bytes, filename)
    except Exception as exc:
        raise HTTPException(422, f"Could not parse stored file: {exc}") from exc

    fixed, changelog = transform(parsed, framework_ids)

    # Output filename
    stem = filename.rsplit(".", 1)[0]
    fw_suffix = "_".join(f.lower() for f in framework_ids)
    out_name = f"{stem}_compliant_{fw_suffix}"

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Fixed file
        fixed_json = json.dumps(fixed, indent=2, ensure_ascii=False)
        zf.writestr(f"{out_name}.json", fixed_json)
        # Changelog
        zf.writestr(
            f"{out_name}_changelog.json",
            json.dumps(changelog, indent=2, ensure_ascii=False),
        )
        # Human-readable summary
        zf.writestr(f"{out_name}_summary.md", _build_md_summary(changelog))

    zip_buf.seek(0)
    return StreamingResponse(
        zip_buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{out_name}.zip"'},
    )


def _build_md_summary(changelog: dict) -> str:
    lines = [
        f"# API Compliance Fix Summary",
        f"",
        f"**Tool:** {changelog.get('tool')} v{changelog.get('version')}",
        f"**Generated:** {changelog.get('generated_at')}",
        f"**Collection:** {changelog.get('collection_name')}",
        f"**Format:** {changelog.get('input_format', 'unknown')}",
        f"**Frameworks:** {', '.join(changelog.get('frameworks', []))}",
        f"**Total changes:** {changelog.get('total_changes', 0)}",
        f"",
        f"## Severity Breakdown",
        f"",
    ]
    sev = changelog.get("severity_summary", {})
    for s in ("critical", "high", "medium", "info"):
        lines.append(f"- **{s.capitalize()}:** {sev.get(s, 0)}")

    lines += ["", "## Changes by Rule", ""]
    for rule in changelog.get("changes_by_rule", []):
        lines.append(f"### [{rule['rule_id']}] {rule['rule_title']}")
        lines.append(f"*{rule.get('reference', '')}* · Severity: **{rule.get('severity', '')}**")
        lines.append("")
        for req in rule.get("affected_requests", []):
            lines.append(f"- `{req['request']}` — {req['detail']}")
        lines.append("")

    return "\n".join(lines)


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "stripe_configured": bool(stripe.api_key),
        "frameworks": list(FRAMEWORK_META.keys()),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
