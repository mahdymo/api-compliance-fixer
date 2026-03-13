"""
Compliance framework definitions.
Each framework declares a set of Rules. A Rule knows how to:
  - detect whether it is violated in a given request/collection
  - fix the violation (mutate in place)
  - report what it changed
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable


# ── Shared low-level helpers ─────────────────────────────────────────────────

def _header_map(headers: list) -> dict[str, int]:
    """Return {lowercase_key: index} for enabled headers."""
    return {h.get("key", "").lower(): i for i, h in enumerate(headers) if not h.get("disabled", False)}


def _add_header(headers: list, key: str, value: str) -> bool:
    if key.lower() not in _header_map(headers):
        headers.append({"key": key, "value": value, "type": "text"})
        return True
    return False


def _set_bearer(request: dict) -> bool:
    auth = request.get("auth") or {}
    if auth.get("type") == "bearer":
        return False
    headers: list = request.setdefault("header", [])
    request["header"] = [h for h in headers if h.get("key", "").lower() != "authorization"]
    request["auth"] = {
        "type": "bearer",
        "bearer": [{"key": "token", "value": "{{access_token}}", "type": "string"}],
    }
    return True


def _method_needs_body(method: str) -> bool:
    return method.upper() in {"POST", "PUT", "PATCH"}


def _ensure_collection_variable(variables: list, key: str, value: str, description: str) -> bool:
    keys = {v.get("key") for v in variables}
    if key not in keys:
        variables.append({"key": key, "value": value, "type": "string", "description": description})
        return True
    return False


def _ensure_https(request: dict) -> bool:
    url = request.get("url", {})
    if isinstance(url, str):
        if url.startswith("http://"):
            request["url"] = url.replace("http://", "https://", 1)
            return True
    elif isinstance(url, dict):
        raw = url.get("raw", "")
        if raw.startswith("http://"):
            url["raw"] = raw.replace("http://", "https://", 1)
            # Also fix protocol array if present
            if "protocol" in url:
                url["protocol"] = "https"
            return True
    return False


def _add_description_tag(request: dict, tag: str) -> bool:
    desc = request.get("description", "")
    if isinstance(desc, str):
        if tag not in desc:
            request["description"] = (desc + f"\n\n[{tag}]").strip()
            return True
    elif isinstance(desc, dict):
        content = desc.get("content", "")
        if tag not in content:
            desc["content"] = (content + f"\n\n[{tag}]").strip()
            return True
    return False


# ── Rule dataclass ───────────────────────────────────────────────────────────

@dataclass
class Rule:
    id: str           # e.g. "SAMA-001"
    title: str
    description: str
    severity: str     # "critical" | "high" | "medium" | "info"
    scope: str        # "request" | "collection"
    reference: str    # clause / article reference

    # Called per-request (scope=="request") or once (scope=="collection")
    # Returns list of change detail strings (empty = no change needed)
    apply: Callable[..., list[str]] = field(repr=False, default=lambda *a: [])


# ── SAMA ─────────────────────────────────────────────────────────────────────

def _sama_rules() -> list[Rule]:
    def r001(request, name, **_):
        headers = request.setdefault("header", [])
        return [f"Added x-otp-id header"] if _add_header(headers, "x-otp-id", "{{otp_id}}") else []

    def r002(request, name, **_):
        headers = request.setdefault("header", [])
        if _method_needs_body(request.get("method", "GET")):
            return [f"Added Content-Type: application/json"] if _add_header(headers, "content-type", "application/json") else []
        return []

    def r003(request, name, **_):
        headers = request.setdefault("header", [])
        added = []
        for hdr, val in [
            ("x-fapi-interaction-id", "{{$guid}}"),
            ("x-fapi-auth-date", "{{$isoTimestamp}}"),
            ("x-fapi-customer-ip-address", "{{client_ip}}"),
        ]:
            if _add_header(headers, hdr, val):
                added.append(hdr)
        return [f"Injected x-fapi headers: {', '.join(added)}"] if added else []

    def r004(request, name, **_):
        return ["Set Bearer {{access_token}} auth"] if _set_bearer(request) else []

    def r005_col(collection, variables, **_):
        added = []
        if _ensure_collection_variable(variables, "tlsVersion", "TLS1_2",
                "Minimum TLS per SAMA OBAPI §6.1"):
            added.append("tlsVersion=TLS1_2")
        for k, v, d in [
            ("access_token", "", "OAuth 2.0 Bearer token"),
            ("otp_id", "", "SAMA OTP session identifier"),
            ("client_ip", "127.0.0.1", "Client IP for x-fapi header"),
        ]:
            _ensure_collection_variable(variables, k, v, d)
        return [f"Added collection variables: {', '.join(added)}"] if added else []

    return [
        Rule("SAMA-001", "x-otp-id Header", "Mandatory OTP session header on every request (SAMA OBAPI §4.3.1)", "critical", "request", "SAMA OBAPI §4.3.1", r001),
        Rule("SAMA-002", "Content-Type: application/json", "Required on all write operations (SAMA OBAPI §3.2)", "high", "request", "SAMA OBAPI §3.2", r002),
        Rule("SAMA-003", "x-fapi-* Headers", "FAPI 1.0 interaction tracing headers (SAMA OBAPI §5.1)", "high", "request", "FAPI 1.0 Advanced · SAMA OBAPI §5.1", r003),
        Rule("SAMA-004", "OAuth 2.0 Bearer Auth", "Replace non-OAuth auth schemes (SAMA OAuth Framework)", "critical", "request", "SAMA OAuth 2.0 Framework", r004),
        Rule("SAMA-005", "TLS 1.2+ Variable", "Collection variable declaring minimum TLS version (SAMA OBAPI §6.1)", "high", "collection", "SAMA OBAPI §6.1", r005_col),
    ]


# ── PCI-DSS ──────────────────────────────────────────────────────────────────

def _pcidss_rules() -> list[Rule]:
    def p001(request, name, **_):
        return ["Enforced HTTPS (TLS in transit)"] if _ensure_https(request) else []

    def p002(request, name, **_):
        return ["Set Bearer {{access_token}} auth — API key auth not PCI-DSS compliant"] if _set_bearer(request) else []

    def p003(request, name, **_):
        headers = request.setdefault("header", [])
        added = []
        for hdr, val in [
            ("X-Request-ID", "{{$guid}}"),
            ("X-Correlation-ID", "{{$guid}}"),
        ]:
            if _add_header(headers, hdr.lower(), val):
                added.append(hdr)
        return [f"Added audit-trail headers: {', '.join(added)}"] if added else []

    def p004(request, name, **_):
        headers = request.setdefault("header", [])
        added = []
        for hdr, val in [
            ("Cache-Control", "no-store"),
            ("Pragma", "no-cache"),
        ]:
            if _add_header(headers, hdr.lower(), val):
                added.append(hdr)
        return [f"Added no-cache headers to prevent CHD storage: {', '.join(added)}"] if added else []

    def p005(request, name, **_):
        headers = request.setdefault("header", [])
        return ["Added Content-Security-Policy header"] if _add_header(headers, "content-security-policy", "default-src 'self'") else []

    def p006_col(collection, variables, **_):
        added = []
        for k, v, d in [
            ("pci_environment", "production", "PCI-DSS target environment"),
            ("access_token", "", "OAuth 2.0 Bearer token"),
        ]:
            if _ensure_collection_variable(variables, k, v, d):
                added.append(k)
        return [f"Added PCI collection variables: {', '.join(added)}"] if added else []

    return [
        Rule("PCI-001", "HTTPS Enforcement", "All cardholder data must be transmitted over TLS (Req 4.2.1)", "critical", "request", "PCI-DSS v4.0 Req 4.2.1", p001),
        Rule("PCI-002", "Strong Authentication", "API-key auth replaced with OAuth 2.0 Bearer (Req 8.3)", "critical", "request", "PCI-DSS v4.0 Req 8.3", p002),
        Rule("PCI-003", "Audit Trail Headers", "X-Request-ID/X-Correlation-ID for log correlation (Req 10.2)", "high", "request", "PCI-DSS v4.0 Req 10.2", p003),
        Rule("PCI-004", "No-Cache Directives", "Prevent CHD caching in intermediaries (Req 4.2.1)", "high", "request", "PCI-DSS v4.0 Req 4.2.1", p004),
        Rule("PCI-005", "Content-Security-Policy", "CSP header to prevent injection in responses (Req 6.4.1)", "medium", "request", "PCI-DSS v4.0 Req 6.4.1", p005),
        Rule("PCI-006", "Collection Variables", "PCI environment variable scaffolding", "info", "collection", "PCI-DSS v4.0 General", p006_col),
    ]


# ── NIS2 ─────────────────────────────────────────────────────────────────────

def _nis2_rules() -> list[Rule]:
    def n001(request, name, **_):
        return ["Enforced HTTPS per NIS2 Art.21 transport security"] if _ensure_https(request) else []

    def n002(request, name, **_):
        return ["Set Bearer {{access_token}} auth (NIS2 Art.21 — strong auth)"] if _set_bearer(request) else []

    def n003(request, name, **_):
        headers = request.setdefault("header", [])
        added = []
        for hdr, val in [
            ("x-request-id", "{{$guid}}"),
            ("x-trace-id", "{{$guid}}"),
        ]:
            if _add_header(headers, hdr, val):
                added.append(hdr)
        return [f"Added incident-traceability headers: {', '.join(added)}"] if added else []

    def n004(request, name, **_):
        headers = request.setdefault("header", [])
        return ["Added X-Frame-Options: DENY"] if _add_header(headers, "x-frame-options", "DENY") else []

    def n005_col(collection, variables, **_):
        added = []
        for k, v, d in [
            ("nis2_contact_email", "", "Security contact per NIS2 Art.20 (responsible disclosure)"),
            ("access_token", "", "OAuth 2.0 Bearer token"),
        ]:
            if _ensure_collection_variable(variables, k, v, d):
                added.append(k)
        return [f"Added NIS2 variables: {', '.join(added)}"] if added else []

    return [
        Rule("NIS2-001", "HTTPS Transport Security", "Encrypted transport for all API communications (Art.21(2)(h))", "critical", "request", "NIS2 Directive Art.21(2)(h)", n001),
        Rule("NIS2-002", "Strong Authentication", "Multi-factor/token-based auth for API access (Art.21(2)(j))", "critical", "request", "NIS2 Directive Art.21(2)(j)", n002),
        Rule("NIS2-003", "Incident Traceability Headers", "Request tracing to support 24h incident reporting (Art.23)", "high", "request", "NIS2 Directive Art.23", n003),
        Rule("NIS2-004", "Clickjacking Protection", "X-Frame-Options to prevent UI redressing (Art.21(2)(e))", "medium", "request", "NIS2 Directive Art.21(2)(e)", n004),
        Rule("NIS2-005", "Security Contact Variable", "Responsible disclosure contact scaffolding (Art.20)", "info", "collection", "NIS2 Directive Art.20", n005_col),
    ]


# ── GDPR ─────────────────────────────────────────────────────────────────────

def _gdpr_rules() -> list[Rule]:
    def g001(request, name, **_):
        return ["Enforced HTTPS — GDPR Art.32 requires appropriate technical measures"] if _ensure_https(request) else []

    def g002(request, name, **_):
        headers = request.setdefault("header", [])
        added = []
        for hdr, val in [
            ("x-data-subject-id", "{{data_subject_id}}"),
            ("x-processing-purpose", "{{processing_purpose}}"),
        ]:
            if _add_header(headers, hdr, val):
                added.append(hdr)
        return [f"Added data-subject traceability headers: {', '.join(added)}"] if added else []

    def g003(request, name, **_):
        headers = request.setdefault("header", [])
        added = []
        for hdr, val in [
            ("cache-control", "no-store, max-age=0"),
            ("pragma", "no-cache"),
        ]:
            if _add_header(headers, hdr, val):
                added.append(hdr)
        return [f"Added no-store directives (GDPR data minimisation): {', '.join(added)}"] if added else []

    def g004(request, name, **_):
        return ["Set Bearer {{access_token}} auth (GDPR Art.32 access control)"] if _set_bearer(request) else []

    def g005(request, name, **_):
        headers = request.setdefault("header", [])
        return ["Added X-Content-Type-Options: nosniff (GDPR Art.25 data integrity)"] if \
            _add_header(headers, "x-content-type-options", "nosniff") else []

    def g006_col(collection, variables, **_):
        added = []
        for k, v, d in [
            ("data_subject_id", "", "GDPR data subject identifier for right-of-access tracking"),
            ("processing_purpose", "contractual", "Legal basis for processing (Art.6 lawful basis)"),
            ("dpa_contact", "", "Data Protection Officer contact email (Art.37)"),
            ("access_token", "", "OAuth 2.0 Bearer token"),
        ]:
            if _ensure_collection_variable(variables, k, v, d):
                added.append(k)
        return [f"Added GDPR variables: {', '.join(added)}"] if added else []

    return [
        Rule("GDPR-001", "HTTPS Transport", "Encryption in transit — appropriate technical measure (Art.32(1)(a))", "critical", "request", "GDPR Art.32(1)(a)", g001),
        Rule("GDPR-002", "Data Subject Headers", "Traceability headers for DSR fulfilment (Art.15–22)", "high", "request", "GDPR Art.15, 17, 20", g002),
        Rule("GDPR-003", "No-Store Directives", "Prevent personal data caching (Art.5 data minimisation)", "high", "request", "GDPR Art.5(1)(c)", g003),
        Rule("GDPR-004", "Authenticated Access", "Bearer token access control for personal data endpoints (Art.32)", "critical", "request", "GDPR Art.32", g004),
        Rule("GDPR-005", "Content-Type Integrity", "X-Content-Type-Options prevents MIME-sniffing of PII (Art.25)", "medium", "request", "GDPR Art.25", g005),
        Rule("GDPR-006", "DPO & Processing Variables", "Variable scaffolding for GDPR record-keeping (Art.30)", "info", "collection", "GDPR Art.30, 37", g006_col),
    ]


# ── DORA ─────────────────────────────────────────────────────────────────────

def _dora_rules() -> list[Rule]:
    def d001(request, name, **_):
        return ["Enforced HTTPS — DORA ICT risk management requires encrypted transport"] if _ensure_https(request) else []

    def d002(request, name, **_):
        return ["Set Bearer {{access_token}} auth (DORA Art.9 access management)"] if _set_bearer(request) else []

    def d003(request, name, **_):
        headers = request.setdefault("header", [])
        added = []
        for hdr, val in [
            ("x-request-id", "{{$guid}}"),
            ("x-transaction-id", "{{$guid}}"),
            ("x-timestamp", "{{$isoTimestamp}}"),
        ]:
            if _add_header(headers, hdr, val):
                added.append(hdr)
        return [f"Added DORA operational-resilience tracing headers: {', '.join(added)}"] if added else []

    def d004(request, name, **_):
        headers = request.setdefault("header", [])
        added = []
        for hdr, val in [
            ("x-retry-after", "{{retry_after_seconds}}"),
            ("x-circuit-breaker", "enabled"),
        ]:
            if _add_header(headers, hdr, val):
                added.append(hdr)
        return [f"Added resilience pattern headers: {', '.join(added)}"] if added else []

    def d005_col(collection, variables, **_):
        added = []
        for k, v, d in [
            ("ict_third_party_id", "", "Third-party ICT provider identifier (DORA Art.28)"),
            ("retry_after_seconds", "30", "Default retry-after for circuit-breaker pattern"),
            ("access_token", "", "OAuth 2.0 Bearer token"),
            ("rto_seconds", "3600", "Recovery Time Objective in seconds (DORA Art.12)"),
        ]:
            if _ensure_collection_variable(variables, k, v, d):
                added.append(k)
        return [f"Added DORA variables: {', '.join(added)}"] if added else []

    def d006(request, name, **_):
        headers = request.setdefault("header", [])
        if _method_needs_body(request.get("method", "GET")):
            return ["Added Content-Type: application/json (DORA data integrity)"] if \
                _add_header(headers, "content-type", "application/json") else []
        return []

    return [
        Rule("DORA-001", "Encrypted Transport", "HTTPS for all ICT service communications (Art.9(2))", "critical", "request", "DORA Art.9(2)", d001),
        Rule("DORA-002", "Access Management", "Token-based auth for ICT operational controls (Art.9(4)(a))", "critical", "request", "DORA Art.9(4)(a)", d002),
        Rule("DORA-003", "Operational Tracing Headers", "Request/transaction IDs for audit log correlation (Art.10)", "high", "request", "DORA Art.10", d003),
        Rule("DORA-004", "Resilience Pattern Headers", "Circuit-breaker and retry signalling (Art.12 — DORA BCP)", "medium", "request", "DORA Art.12", d004),
        Rule("DORA-005", "ICT Provider Variables", "Third-party provider ID and RTO variable scaffolding (Art.28)", "info", "collection", "DORA Art.28", d005_col),
        Rule("DORA-006", "Data Integrity Headers", "Content-Type enforcement for ICT data exchange (Art.9)", "high", "request", "DORA Art.9", d006),
    ]


# ── Registry ─────────────────────────────────────────────────────────────────

FRAMEWORK_META = {
    "SAMA": {
        "id": "SAMA",
        "name": "SAMA Open Banking",
        "full_name": "Saudi Arabian Monetary Authority — Open Banking API Framework",
        "description": "Compliance framework for financial institutions operating under SAMA's Open Banking regulatory mandate in Saudi Arabia.",
        "color": "#00c8ff",
        "icon": "🇸🇦",
        "regions": ["KSA"],
        "version": "SAMA OBAPI v1.0",
    },
    "PCIDSS": {
        "id": "PCIDSS",
        "name": "PCI-DSS v4.0",
        "full_name": "Payment Card Industry Data Security Standard v4.0",
        "description": "Security standard for all entities that store, process, or transmit cardholder data.",
        "color": "#ff9500",
        "icon": "💳",
        "regions": ["Global"],
        "version": "PCI-DSS v4.0 (2022)",
    },
    "NIS2": {
        "id": "NIS2",
        "name": "NIS2 Directive",
        "full_name": "EU Network and Information Security Directive 2 (2022/2555)",
        "description": "EU cybersecurity directive for critical infrastructure and essential service operators.",
        "color": "#0055ff",
        "icon": "🇪🇺",
        "regions": ["EU/EEA"],
        "version": "NIS2 (EU) 2022/2555",
    },
    "GDPR": {
        "id": "GDPR",
        "name": "GDPR",
        "full_name": "EU General Data Protection Regulation (2016/679)",
        "description": "EU data protection regulation governing personal data processing, privacy rights, and controller obligations.",
        "color": "#00e5a0",
        "icon": "🔒",
        "regions": ["EU/EEA", "Global (data subjects)"],
        "version": "GDPR (EU) 2016/679",
    },
    "DORA": {
        "id": "DORA",
        "name": "DORA",
        "full_name": "EU Digital Operational Resilience Act (2022/2554)",
        "description": "EU regulation requiring financial entities to ensure ICT operational resilience, including API security and third-party risk.",
        "color": "#ff5c8a",
        "icon": "🏦",
        "regions": ["EU/EEA"],
        "version": "DORA (EU) 2022/2554",
    },
}

FRAMEWORK_RULES: dict[str, list[Rule]] = {
    "SAMA": _sama_rules(),
    "PCIDSS": _pcidss_rules(),
    "NIS2": _nis2_rules(),
    "GDPR": _gdpr_rules(),
    "DORA": _dora_rules(),
}
