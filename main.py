"""
API Compliance Fixer — FastAPI Backend v3
Payment providers: Stripe + PayPal
Supports: Postman v2/v2.1 collections + OpenAPI 3.x specs
Frameworks: SAMA, PCI-DSS, NIS2, GDPR, DORA
"""
from __future__ import annotations

import base64
import io
import json
import os
import secrets
import zipfile
from pathlib import Path

import httpx
import stripe
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from frameworks import FRAMEWORK_META, FRAMEWORK_RULES
from transform import detect_format, preview, transform

# ── Stripe ────────────────────────────────────────────────────────────────────
stripe.api_key        = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# ── PayPal ────────────────────────────────────────────────────────────────────
PAYPAL_CLIENT_ID     = os.getenv("PAYPAL_CLIENT_ID", "")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
PAYPAL_ENV           = os.getenv("PAYPAL_ENV", "sandbox")
PAYPAL_BASE = (
    "https://api-m.sandbox.paypal.com"
    if PAYPAL_ENV != "live"
    else "https://api-m.paypal.com"
)

# ── App ────────────────────────────────────────────────────────────────────────
BASE_URL      = os.getenv("BASE_URL", "http://localhost:8000")
PRICE_CENTS   = int(os.getenv("PRICE_CENTS", "2900"))
PRICE_DOLLARS = f"{PRICE_CENTS / 100:.2f}"

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
VALID_FRAMEWORKS = set(FRAMEWORK_META.keys())

# ── In-memory stores ──────────────────────────────────────────────────────────
pending_uploads:   dict[str, dict] = {}   # upload_token  → entry
paid_tokens:       dict[str, dict] = {}   # download_token → entry
stripe_session_map: dict[str, str] = {}   # stripe session_id → upload_token
paypal_order_map:   dict[str, str] = {}   # paypal order_id   → upload_token

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(title="API Compliance Fixer", version="3.0.0")
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
        return d.get("info", {}).get("name" if entry["format"] == "postman" else "title", "API File")
    except Exception:
        return "API File"


def _fw_label(entry: dict) -> str:
    return " + ".join(FRAMEWORK_META[f]["name"] for f in entry["frameworks"] if f in FRAMEWORK_META)


def _redirect_html(dl_token: str) -> HTMLResponse:
    return HTMLResponse(
        f'<!DOCTYPE html><html><head>'
        f'<meta http-equiv="refresh" content="0;url=/?download_token={dl_token}&success=1">'
        f'</head><body>Redirecting…</body></html>'
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PAYPAL REST HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

async def _pp_token() -> str:
    creds = base64.b64encode(f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}".encode()).decode()
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{PAYPAL_BASE}/v1/oauth2/token",
            headers={"Authorization": f"Basic {creds}", "Content-Type": "application/x-www-form-urlencoded"},
            data="grant_type=client_credentials",
            timeout=15,
        )
    if r.status_code != 200:
        raise HTTPException(502, f"PayPal auth failed: {r.text}")
    return r.json()["access_token"]


async def _pp_create_order(upload_token: str, col_name: str, fw_label: str) -> dict:
    tok = await _pp_token()
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{PAYPAL_BASE}/v2/checkout/orders",
            headers={
                "Authorization": f"Bearer {tok}",
                "Content-Type": "application/json",
                "PayPal-Request-Id": secrets.token_urlsafe(16),
            },
            json={
                "intent": "CAPTURE",
                "purchase_units": [{
                    "reference_id": upload_token,
                    "custom_id": upload_token,
                    "description": f"{col_name} · {fw_label}",
                    "amount": {"currency_code": "USD", "value": PRICE_DOLLARS},
                }],
                "application_context": {
                    "brand_name": "API Compliance Fixer",
                    "landing_page": "BILLING",
                    "user_action": "PAY_NOW",
                    "return_url": f"{BASE_URL}/api/paypal/success",
                    "cancel_url": f"{BASE_URL}/",
                },
            },
            timeout=15,
        )
    if r.status_code not in (200, 201):
        raise HTTPException(502, f"PayPal order creation failed: {r.text}")
    return r.json()


async def _pp_capture(order_id: str) -> dict:
    tok = await _pp_token()
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{PAYPAL_BASE}/v2/checkout/orders/{order_id}/capture",
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            timeout=15,
        )
    if r.status_code not in (200, 201):
        raise HTTPException(502, f"PayPal capture failed: {r.text}")
    return r.json()


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — CORE
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
        "status": "ok", "version": "3.0.0",
        "stripe_configured": bool(stripe.api_key),
        "paypal_configured": bool(PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET),
        "paypal_env": PAYPAL_ENV,
        "frameworks": list(FRAMEWORK_META.keys()),
    }


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
    changelog = preview(parsed, fw_ids)
    token = secrets.token_urlsafe(32)
    pending_uploads[token] = {"raw": raw, "filename": filename, "frameworks": fw_ids, "format": fmt}
    return {"upload_token": token, "format": fmt, "changelog_preview": changelog}


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — STRIPE
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/checkout/stripe/{upload_token}")
async def stripe_checkout(upload_token: str):
    entry = pending_uploads.get(upload_token)
    if not entry:
        raise HTTPException(404, "Upload not found or expired.")
    if not stripe.api_key:
        raise HTTPException(503, "Stripe not configured — set STRIPE_SECRET_KEY.")
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price_data": {"currency": "usd", "unit_amount": PRICE_CENTS,
                "product_data": {"name": "API Compliance Fixer",
                                 "description": f"{_col_name(entry)} · {_fw_label(entry)}"}},
                "quantity": 1}],
            mode="payment",
            success_url=f"{BASE_URL}/api/stripe/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}/",
            metadata={"upload_token": upload_token},
        )
    except stripe.StripeError as exc:
        raise HTTPException(502, f"Stripe error: {exc.user_message}") from exc
    stripe_session_map[session.id] = upload_token
    return {"checkout_url": session.url, "provider": "stripe"}


@app.get("/api/stripe/success", response_class=HTMLResponse)
async def stripe_success(session_id: str):
    try:
        session = stripe.checkout.Session.retrieve(session_id)
    except stripe.StripeError as exc:
        raise HTTPException(502, str(exc)) from exc
    if session.payment_status != "paid":
        raise HTTPException(402, "Payment not completed.")
    upload_token = session.metadata.get("upload_token") or stripe_session_map.get(session_id)
    if not upload_token or upload_token not in pending_uploads:
        raise HTTPException(404, "Upload not found — it may have expired.")
    entry = pending_uploads.pop(upload_token)
    dl_token = secrets.token_urlsafe(32)
    paid_tokens[dl_token] = entry
    return _redirect_html(dl_token)


@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    if STRIPE_WEBHOOK_SECRET:
        try:
            stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
        except stripe.SignatureVerificationError:
            raise HTTPException(400, "Invalid Stripe webhook signature.")
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — PAYPAL
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/checkout/paypal/{upload_token}")
async def paypal_checkout(upload_token: str):
    entry = pending_uploads.get(upload_token)
    if not entry:
        raise HTTPException(404, "Upload not found or expired.")
    if not (PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET):
        raise HTTPException(503, "PayPal not configured — set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET.")
    order = await _pp_create_order(upload_token, _col_name(entry), _fw_label(entry))
    order_id = order["id"]
    paypal_order_map[order_id] = upload_token
    approve_url = next((l["href"] for l in order.get("links", []) if l["rel"] == "approve"), None)
    if not approve_url:
        raise HTTPException(502, "PayPal did not return an approval URL.")
    return {"order_id": order_id, "approve_url": approve_url, "provider": "paypal"}


@app.get("/api/paypal/success", response_class=HTMLResponse)
async def paypal_success(token: str = "", PayerID: str = ""):
    order_id = token
    if not order_id:
        raise HTTPException(400, "Missing PayPal order token.")
    capture = await _pp_capture(order_id)
    if capture.get("status") != "COMPLETED":
        raise HTTPException(402, f"PayPal payment not completed (status: {capture.get('status')}).")
    upload_token = paypal_order_map.get(order_id)
    if not upload_token:
        try:
            upload_token = capture["purchase_units"][0]["reference_id"]
        except (KeyError, IndexError):
            pass
    if not upload_token or upload_token not in pending_uploads:
        raise HTTPException(404, "Original upload not found — it may have expired.")
    entry = pending_uploads.pop(upload_token)
    paypal_order_map.pop(order_id, None)
    dl_token = secrets.token_urlsafe(32)
    paid_tokens[dl_token] = entry
    return _redirect_html(dl_token)


@app.post("/api/paypal/webhook")
async def paypal_webhook(request: Request):
    try:
        event = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON.")
    if event.get("event_type") == "PAYMENT.CAPTURE.COMPLETED":
        resource = event.get("resource", {})
        custom_id = resource.get("custom_id")
        if custom_id and custom_id in pending_uploads:
            entry = pending_uploads.pop(custom_id)
            dl_token = secrets.token_urlsafe(32)
            paid_tokens[dl_token] = entry
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — DOWNLOAD
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/download/{download_token}")
async def download(download_token: str):
    entry = paid_tokens.pop(download_token, None)
    if not entry:
        raise HTTPException(404, "Download token not found or already used.")
    raw_bytes    = entry["raw"]
    framework_ids = entry["frameworks"]
    filename     = entry.get("filename", "collection.json")
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
