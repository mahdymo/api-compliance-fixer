"""
API Compliance Fixer — Transform Engine
Supports: Postman Collection v2/v2.1, OpenAPI 3.x (JSON/YAML)
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any

from frameworks import FRAMEWORK_META, FRAMEWORK_RULES, Rule


# ── Format detection ─────────────────────────────────────────────────────────

def detect_format(raw: dict) -> str:
    """Returns 'postman' or 'openapi' or raises ValueError."""
    if "info" in raw and "item" in raw:
        return "postman"
    if "openapi" in raw or "swagger" in raw:
        return "openapi"
    raise ValueError("Unrecognised file format. Expected Postman v2 collection or OpenAPI 3.x spec.")


# ═════════════════════════════════════════════════════════════════════════════
# POSTMAN TRANSFORMER
# ═════════════════════════════════════════════════════════════════════════════

def _walk_postman_items(items: list, rules: list[Rule]) -> list[dict]:
    all_changes = []
    for item in items:
        if "item" in item:
            all_changes.extend(_walk_postman_items(item["item"], rules))
        elif "request" in item:
            name = item.get("name", "Unnamed Request")
            req = item["request"]
            for rule in rules:
                if rule.scope != "request":
                    continue
                details = rule.apply(request=req, name=name)
                for detail in details:
                    all_changes.append({
                        "rule_id": rule.id,
                        "rule_title": rule.title,
                        "severity": rule.severity,
                        "reference": rule.reference,
                        "request": name,
                        "detail": detail,
                    })
    return all_changes


def transform_postman(raw: dict, framework_ids: list[str]) -> tuple[dict, dict]:
    collection = copy.deepcopy(raw)
    all_changes: list[dict] = []

    active_rules: list[Rule] = []
    for fid in framework_ids:
        active_rules.extend(FRAMEWORK_RULES.get(fid, []))

    # Request-scoped rules
    items = collection.get("item", [])
    all_changes.extend(_walk_postman_items(items, active_rules))

    # Collection-scoped rules
    variables: list = collection.setdefault("variable", [])
    for rule in active_rules:
        if rule.scope == "collection":
            details = rule.apply(collection=collection, variables=variables)
            for detail in details:
                all_changes.append({
                    "rule_id": rule.id,
                    "rule_title": rule.title,
                    "severity": rule.severity,
                    "reference": rule.reference,
                    "request": "(collection-level)",
                    "detail": detail,
                })

    changelog = _build_changelog(
        raw.get("info", {}).get("name", "Unknown"),
        "postman",
        framework_ids,
        all_changes,
        active_rules,
    )
    return collection, changelog


# ═════════════════════════════════════════════════════════════════════════════
# OPENAPI TRANSFORMER
# ═════════════════════════════════════════════════════════════════════════════

def _openapi_header_exists(operation: dict, header_name: str) -> bool:
    params = operation.get("parameters", [])
    for p in params:
        if p.get("in") == "header" and p.get("name", "").lower() == header_name.lower():
            return True
    return False


def _add_openapi_header_param(operation: dict, name: str, description: str, required: bool = False) -> bool:
    if _openapi_header_exists(operation, name):
        return False
    operation.setdefault("parameters", []).append({
        "name": name,
        "in": "header",
        "required": required,
        "description": description,
        "schema": {"type": "string"},
    })
    return True


def _openapi_has_bearer(operation: dict, spec: dict) -> bool:
    security = operation.get("security") or spec.get("security") or []
    for s in security:
        if any("bearer" in k.lower() or "oauth" in k.lower() for k in s):
            return True
    components = spec.get("components", {}).get("securitySchemes", {})
    for k in components:
        if components[k].get("type") in ("oauth2", "http") and \
           components[k].get("scheme", "").lower() == "bearer":
            return True
    return False


def _ensure_openapi_bearer(spec: dict) -> bool:
    components = spec.setdefault("components", {})
    schemes = components.setdefault("securitySchemes", {})
    if "BearerAuth" not in schemes:
        schemes["BearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "OAuth 2.0 Bearer token",
        }
        # Apply globally
        spec.setdefault("security", [])
        if {"BearerAuth": []} not in spec["security"]:
            spec["security"].append({"BearerAuth": []})
        return True
    return False


def _ensure_openapi_https(spec: dict) -> bool:
    servers = spec.get("servers", [])
    changed = False
    for s in servers:
        url = s.get("url", "")
        if url.startswith("http://"):
            s["url"] = url.replace("http://", "https://", 1)
            changed = True
    # Also add x-minimum-tls extension
    if "x-minimum-tls" not in spec:
        spec["x-minimum-tls"] = "TLS1_2"
        changed = True
    return changed


def _openapi_operation_name(method: str, path: str, op: dict) -> str:
    return op.get("operationId") or op.get("summary") or f"{method.upper()} {path}"


def transform_openapi(raw: dict, framework_ids: list[str]) -> tuple[dict, dict]:
    spec = copy.deepcopy(raw)
    all_changes: list[dict] = []

    active_rules: list[Rule] = []
    for fid in framework_ids:
        active_rules.extend(FRAMEWORK_RULES.get(fid, []))

    http_methods = {"get", "post", "put", "patch", "delete", "head", "options"}
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        for method, operation in path_item.items():
            if method.lower() not in http_methods:
                continue
            if not isinstance(operation, dict):
                continue

            op_name = _openapi_operation_name(method, path, operation)

            # Map framework rules to OpenAPI operations
            for fid in framework_ids:
                for rule in FRAMEWORK_RULES.get(fid, []):
                    if rule.scope != "request":
                        continue

                    details = _apply_rule_to_openapi_op(rule, fid, spec, path, method, operation, op_name)
                    for detail in details:
                        all_changes.append({
                            "rule_id": rule.id,
                            "rule_title": rule.title,
                            "severity": rule.severity,
                            "reference": rule.reference,
                            "request": op_name,
                            "detail": detail,
                        })

    # Collection/spec-level rules
    _apply_openapi_spec_level(spec, framework_ids, all_changes, active_rules)

    title = spec.get("info", {}).get("title", "Unknown")
    changelog = _build_changelog(title, "openapi", framework_ids, all_changes, active_rules)
    return spec, changelog


def _apply_rule_to_openapi_op(
    rule: Rule, fid: str, spec: dict, path: str, method: str, operation: dict, op_name: str
) -> list[str]:
    """Translate Postman-style rules into OpenAPI parameter/security mutations."""
    details = []
    rule_id = rule.id

    # ── SAMA ──
    if rule_id == "SAMA-001":
        if _add_openapi_header_param(operation, "x-otp-id", "SAMA OTP session identifier (SAMA OBAPI §4.3.1)", required=True):
            details.append("Added x-otp-id header parameter")

    elif rule_id == "SAMA-002":
        if method.lower() in ("post", "put", "patch"):
            rb = operation.setdefault("requestBody", {})
            content = rb.setdefault("content", {})
            if "application/json" not in content:
                content["application/json"] = {"schema": {"type": "object"}}
                details.append("Added application/json request body schema")

    elif rule_id == "SAMA-003":
        for hdr, desc in [
            ("x-fapi-interaction-id", "FAPI interaction correlation ID"),
            ("x-fapi-auth-date", "FAPI auth date (ISO 8601)"),
            ("x-fapi-customer-ip-address", "Customer IP address"),
        ]:
            if _add_openapi_header_param(operation, hdr, desc):
                details.append(f"Added {hdr} parameter")

    elif rule_id == "SAMA-004":
        if _ensure_openapi_bearer(spec):
            details.append("Added BearerAuth security scheme and global security requirement")

    # ── PCI ──
    elif rule_id == "PCI-002":
        if _ensure_openapi_bearer(spec):
            details.append("Added BearerAuth — API-key auth not PCI-DSS compliant")

    elif rule_id == "PCI-003":
        for hdr, desc in [
            ("X-Request-ID", "Audit trail request identifier"),
            ("X-Correlation-ID", "Cross-service correlation identifier"),
        ]:
            if _add_openapi_header_param(operation, hdr, desc):
                details.append(f"Added {hdr} parameter")

    # ── NIS2 ──
    elif rule_id == "NIS2-002":
        if _ensure_openapi_bearer(spec):
            details.append("Added BearerAuth (NIS2 Art.21 strong auth)")

    elif rule_id == "NIS2-003":
        for hdr, desc in [
            ("x-request-id", "NIS2 incident traceability request ID"),
            ("x-trace-id", "NIS2 cross-system trace ID"),
        ]:
            if _add_openapi_header_param(operation, hdr, desc):
                details.append(f"Added {hdr} parameter")

    # ── GDPR ──
    elif rule_id == "GDPR-002":
        for hdr, desc in [
            ("x-data-subject-id", "GDPR data subject identifier"),
            ("x-processing-purpose", "Legal basis for processing (Art.6)"),
        ]:
            if _add_openapi_header_param(operation, hdr, desc):
                details.append(f"Added {hdr} parameter")

    elif rule_id == "GDPR-004":
        if _ensure_openapi_bearer(spec):
            details.append("Added BearerAuth (GDPR Art.32 access control)")

    # ── DORA ──
    elif rule_id == "DORA-002":
        if _ensure_openapi_bearer(spec):
            details.append("Added BearerAuth (DORA Art.9 access management)")

    elif rule_id == "DORA-003":
        for hdr, desc in [
            ("x-request-id", "DORA operational tracing request ID"),
            ("x-transaction-id", "DORA financial transaction ID"),
            ("x-timestamp", "Request timestamp (ISO 8601)"),
        ]:
            if _add_openapi_header_param(operation, hdr, desc):
                details.append(f"Added {hdr} parameter")

    elif rule_id == "DORA-004":
        for hdr, desc in [
            ("x-retry-after", "Circuit-breaker retry interval (seconds)"),
            ("x-circuit-breaker", "Circuit-breaker state indicator"),
        ]:
            if _add_openapi_header_param(operation, hdr, desc):
                details.append(f"Added {hdr} parameter")

    return details


def _apply_openapi_spec_level(spec: dict, framework_ids: list[str], all_changes: list, active_rules: list[Rule]):
    for fid in framework_ids:
        # HTTPS / TLS
        if fid in ("SAMA", "PCIDSS", "NIS2", "GDPR", "DORA"):
            if _ensure_openapi_https(spec):
                rule = next((r for r in active_rules if r.id.endswith("-001")), None)
                ref = rule.reference if rule else f"{fid} transport security"
                all_changes.append({
                    "rule_id": f"{fid}-001",
                    "rule_title": "HTTPS / TLS Enforcement",
                    "severity": "critical",
                    "reference": ref,
                    "request": "(spec-level)",
                    "detail": "Enforced HTTPS on all server URLs; added x-minimum-tls: TLS1_2",
                })
        # Compliance extensions
        spec.setdefault("x-compliance", {})[fid] = {
            "framework": FRAMEWORK_META[fid]["full_name"],
            "applied_at": datetime.now(timezone.utc).isoformat(),
        }


# ═════════════════════════════════════════════════════════════════════════════
# UNIFIED INTERFACE
# ═════════════════════════════════════════════════════════════════════════════

def preview(raw: dict, framework_ids: list[str]) -> dict:
    """Return changelog preview without persisting any changes."""
    fmt = detect_format(raw)
    if fmt == "postman":
        _, changelog = transform_postman(raw, framework_ids)
    else:
        _, changelog = transform_openapi(raw, framework_ids)
    return changelog


def transform(raw: dict, framework_ids: list[str]) -> tuple[dict, dict]:
    fmt = detect_format(raw)
    if fmt == "postman":
        return transform_postman(raw, framework_ids)
    else:
        return transform_openapi(raw, framework_ids)


# ── Changelog builder ────────────────────────────────────────────────────────

def _build_changelog(
    name: str,
    format_type: str,
    framework_ids: list[str],
    all_changes: list[dict],
    active_rules: list[Rule],
) -> dict:
    # Group by rule_id
    rule_summary: dict[str, dict] = {}
    for c in all_changes:
        rid = c["rule_id"]
        if rid not in rule_summary:
            rule_summary[rid] = {
                "rule_id": rid,
                "rule_title": c["rule_title"],
                "severity": c["severity"],
                "reference": c["reference"],
                "affected_requests": [],
            }
        rule_summary[rid]["affected_requests"].append({
            "request": c["request"],
            "detail": c["detail"],
        })

    # Severity counts
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    for c in all_changes:
        sev_counts[c.get("severity", "info")] += 1

    frameworks_detail = []
    for fid in framework_ids:
        meta = FRAMEWORK_META.get(fid, {})
        fw_rules = [r for r in active_rules if r.id.startswith(fid)]
        frameworks_detail.append({
            "id": fid,
            "name": meta.get("name", fid),
            "full_name": meta.get("full_name", ""),
            "version": meta.get("version", ""),
            "rules_applied": len(fw_rules),
            "changes_made": sum(1 for c in all_changes if c["rule_id"].startswith(fid)),
        })

    return {
        "tool": "API Compliance Fixer",
        "version": "2.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "collection_name": name,
        "input_format": format_type,
        "frameworks": framework_ids,
        "frameworks_detail": frameworks_detail,
        "total_changes": len(all_changes),
        "severity_summary": sev_counts,
        "changes_by_rule": list(rule_summary.values()),
        "rule_definitions": [
            {
                "id": r.id,
                "title": r.title,
                "description": r.description,
                "severity": r.severity,
                "reference": r.reference,
                "scope": r.scope,
            }
            for r in active_rules
        ],
    }
