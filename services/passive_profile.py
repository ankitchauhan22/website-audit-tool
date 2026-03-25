import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


TECHNOLOGY_SECTIONS = [
    {
        "title": "Edge and Delivery",
        "description": "CDNs, reverse proxies, caching layers, and edge infrastructure.",
        "categories": {"CDN", "Performance", "Proxy", "Hosting"},
    },
    {
        "title": "Application Platform",
        "description": "CMS, commerce, hosting, and server-side runtime clues.",
        "categories": {"CMS", "Commerce", "Runtime", "Hosting"},
    },
    {
        "title": "Frontend Experience",
        "description": "Frameworks, UI libraries, and client-side delivery patterns.",
        "categories": {"Frontend", "JavaScript Library"},
    },
    {
        "title": "Analytics and Marketing",
        "description": "Tracking, tag management, consent, chat, and campaign tooling.",
        "categories": {"Analytics", "Marketing", "Tag Manager", "Consent", "Customer Support"},
    },
    {
        "title": "Security and Compliance",
        "description": "Bot protection, WAF, fraud prevention, and security controls.",
        "categories": {"Security"},
    },
    {
        "title": "Data and Storage",
        "description": "Database and caching technologies inferred from public signals.",
        "categories": {"Database"},
    },
]


def _strip_www(hostname: str) -> str:
    return (hostname or "").lower().removeprefix("www.")


def fetch_tls_profile(final_url: str, timeout: float = 4.0) -> dict:
    """Collect certificate identity and validity details for HTTPS targets."""
    parsed = urlparse(final_url)
    hostname = parsed.hostname or ""
    port = parsed.port or 443

    if parsed.scheme != "https" or not hostname:
        return {
            "scheme": parsed.scheme or "unknown",
            "hostname": hostname or "unknown",
            "status": "Not applicable",
            "detail": "TLS inspection only applies when the final URL resolves over HTTPS.",
        }

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_socket:
                certificate = tls_socket.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return {
            "scheme": "https",
            "hostname": hostname,
            "status": "Certificate validation failed",
            "detail": str(exc),
        }
    except OSError as exc:
        return {
            "scheme": "https",
            "hostname": hostname,
            "status": "TLS inspection unavailable",
            "detail": str(exc),
        }

    issuer = dict(item[0] for item in certificate.get("issuer", []) if item)
    subject = dict(item[0] for item in certificate.get("subject", []) if item)
    sans = [entry[1] for entry in certificate.get("subjectAltName", []) if len(entry) > 1]
    not_after_raw = certificate.get("notAfter")
    expires_in_days = None
    validity_status = "Valid"

    if not_after_raw:
        expires_at = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        expires_in_days = (expires_at - datetime.now(timezone.utc)).days
        if expires_in_days < 0:
            validity_status = "Expired"
        elif expires_in_days < 30:
            validity_status = "Expiring soon"

    covered_names = {hostname.lower(), *[name.lower() for name in sans]}
    hostname_covered = any(
        name == hostname.lower()
        or (name.startswith("*.") and hostname.lower().endswith(name[1:]))
        for name in covered_names
    )

    return {
        "scheme": "https",
        "hostname": hostname,
        "status": validity_status,
        "detail": f"Issued by {issuer.get('organizationName') or issuer.get('commonName') or 'Unknown issuer'}.",
        "subject": subject.get("commonName", "Not exposed"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Not exposed",
        "san_count": len(sans),
        "expires_in_days": expires_in_days,
        "hostname_covered": hostname_covered,
    }


def build_transport_profile(final_url: str, headers, fetch_warning: str | None = None, tls_profile: dict | None = None):
    """Summarize transport- and cache-related response signals."""
    parsed = urlparse(final_url)
    is_https = parsed.scheme == "https"
    http_version = headers.get("X-Audit-HTTP-Version", "Not detected")
    alt_svc = headers.get("Alt-Svc", "")
    profile = [
        {
            "check": "HTTPS",
            "value": "Enabled" if is_https else "Not enabled",
            "detail": "Final page load uses HTTPS" if is_https else "Final page load does not use HTTPS",
        },
        {
            "check": "HSTS",
            "value": "Enabled" if "Strict-Transport-Security" in headers else "Not exposed",
            "detail": "Header present" if "Strict-Transport-Security" in headers else "Header not exposed",
        },
        {
            "check": "Compression",
            "value": headers.get("Content-Encoding", "Not exposed"),
            "detail": "HTTP content encoding returned by the origin or proxy",
        },
        {
            "check": "Cache Control",
            "value": headers.get("Cache-Control", "Not exposed"),
            "detail": "Caching directives surfaced in the response",
        },
        {
            "check": "HTTP Protocol",
            "value": "HTTP/3 available" if "h3" in alt_svc.lower() else http_version,
            "detail": "Protocol observed during fetch or advertised via Alt-Svc.",
        },
    ]

    if tls_profile:
        expiry_detail = tls_profile.get("detail", "TLS inspection completed.")
        if tls_profile.get("expires_in_days") is not None:
            expiry_detail = f"{expiry_detail} Certificate expires in {tls_profile['expires_in_days']} day(s)."
        profile.extend(
            [
                {
                    "check": "TLS Validation",
                    "value": tls_profile.get("status", "Unknown"),
                    "detail": expiry_detail,
                },
                {
                    "check": "Certificate Host Coverage",
                    "value": "Matches hostname" if tls_profile.get("hostname_covered") else "Review required",
                    "detail": f"Certificate subject: {tls_profile.get('subject', 'Not exposed')}",
                },
            ]
        )

    if fetch_warning:
        profile.append(
            {
                "check": "TLS Fetch Path",
                "value": "Warning",
                "detail": fetch_warning,
            }
        )

    return profile


def build_domain_identity_profile(requested_url: str, final_url: str, headers, tls_profile: dict | None = None) -> list[dict]:
    """Summarize redirect, hostname, and certificate identity signals."""
    requested = urlparse(requested_url if "://" in requested_url else f"https://{requested_url}")
    final = urlparse(final_url)
    requested_host = requested.hostname or ""
    final_host = final.hostname or ""
    same_domain = _strip_www(requested_host) == _strip_www(final_host)

    profile = [
        {
            "check": "Resolved Hostname",
            "value": final_host or "Not resolved",
            "detail": "Final hostname reached by the passive scan.",
        },
        {
            "check": "Host Consistency",
            "value": "Aligned" if same_domain else "Review redirect target",
            "detail": (
                f"Requested host {requested_host or 'unknown'} resolved to {final_host or 'unknown'}."
            ),
        },
        {
            "check": "Canonical Redirect",
            "value": "Present" if requested.geturl() != final.geturl() else "Not observed",
            "detail": (
                f"Requested URL redirected to {final.geturl()}."
                if requested.geturl() != final.geturl()
                else "No redirect was required for the requested page."
            ),
        },
        {
            "check": "Server Identity",
            "value": headers.get("Server", "Not exposed"),
            "detail": "Origin or edge server identity exposed in public headers.",
        },
    ]

    if tls_profile:
        profile.append(
            {
                "check": "Certificate Issuer",
                "value": tls_profile.get("issuer", "Not exposed"),
                "detail": tls_profile.get("detail", "TLS certificate details were collected from the final host."),
            }
        )

    return profile


def analyze_cookie_headers(set_cookie_headers):
    """Report missing security attributes on exposed Set-Cookie headers."""
    analysis = []

    priority_map = {
        "must": "P1",
        "high": "P2",
        "monitor": "P3",
        "good": "P4",
    }

    for raw_cookie in set_cookie_headers:
        parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
        if not parts:
            continue

        cookie_name = parts[0].split("=", 1)[0]
        normalized = {part.lower() for part in parts[1:]}
        issues = []
        severity = "good"
        is_session_like = any(token in cookie_name.lower() for token in ("sess", "auth", "token", "login"))

        if "secure" not in normalized and not cookie_name.startswith("__Secure-"):
            issues.append("Missing Secure flag")
            severity = "must" if is_session_like else "high"
        if "httponly" not in normalized:
            issues.append("Missing HttpOnly flag")
            if severity != "must":
                severity = "must" if is_session_like else "high"
        if not any(part.lower().startswith("samesite=") for part in parts[1:]):
            issues.append("Missing SameSite attribute")
            if severity == "good":
                severity = "monitor"

        analysis.append(
            {
                "name": cookie_name,
                "issue": ", ".join(issues) if issues else "No obvious attribute gap in exposed header",
                "severity": severity,
                "priority": priority_map.get(severity, "P3"),
                "is_insecure": bool(issues),
                "is_session_like": is_session_like,
                "detail": (
                    "Cookie name suggests session or authentication state."
                    if is_session_like
                    else "Public Set-Cookie header exposed on the scanned page set."
                ),
            }
        )

    return analysis


def group_stack_signals(technology_stack):
    """Group passive detections into stable, presentation-friendly sections."""
    grouped = []
    for section in TECHNOLOGY_SECTIONS:
        items = [
            item for item in technology_stack if item["category"] in section["categories"]
        ]
        if not items:
            continue
        items = sorted(
            items,
            key=lambda item: (-item.get("confidence_score", 0), item.get("name", "").lower()),
        )
        risk_count = sum(
            1 for item in items if item.get("status") in {"Outdated", "Deprecated"}
        )
        current_count = sum(1 for item in items if item.get("status") == "Current")
        review_count = sum(1 for item in items if item.get("status") == "Review")
        managed_count = sum(1 for item in items if item.get("status") == "Managed")
        unverified_count = sum(
            1
            for item in items
            if item.get("detected_version") == "Not publicly exposed"
        )
        if risk_count:
            summary = (
                f"{risk_count} technology finding{'s' if risk_count != 1 else ''} in this section need urgent lifecycle remediation."
            )
        elif review_count:
            summary = (
                f"{review_count} technology finding{'s' if review_count != 1 else ''} should be reviewed against the current supported release line."
            )
        elif unverified_count:
            noun = "finding was" if unverified_count == 1 else "findings were"
            summary = (
                f"{unverified_count} technology {noun} identified but the exact version was not exposed publicly. "
                "Confirm installed versions internally and patch unsupported releases."
            )
        elif current_count or managed_count:
            total_verified = current_count + managed_count
            verb = "was" if total_verified == 1 else "were"
            summary = (
                f"{current_count} current and {managed_count} managed technology finding{'s' if total_verified != 1 else ''} {verb} verified from public evidence."
            )
        else:
            summary = (
                f"{len(items)} publicly visible signal{'s' if len(items) != 1 else ''} support this section, "
                "but version and lifecycle certainty still depend on the exposed evidence."
            )
        grouped.append(
            {
                "title": section["title"],
                "description": section["description"],
                "risk_count": risk_count,
                "review_count": review_count,
                "unverified_count": unverified_count,
                "summary": summary,
                "items": items,
            }
        )
    return grouped
