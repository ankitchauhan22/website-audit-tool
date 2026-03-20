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


def build_transport_profile(final_url: str, headers):
    """Summarize transport- and cache-related response signals."""
    parsed = urlparse(final_url)
    is_https = parsed.scheme == "https"
    return [
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
    ]


def analyze_cookie_headers(set_cookie_headers):
    """Report missing security attributes on exposed Set-Cookie headers."""
    analysis = []

    for raw_cookie in set_cookie_headers:
        parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
        if not parts:
            continue

        cookie_name = parts[0].split("=", 1)[0]
        normalized = {part.lower() for part in parts[1:]}
        issues = []
        if "secure" not in normalized and not cookie_name.startswith("__Secure-"):
            issues.append("Missing Secure flag")
        if "httponly" not in normalized:
            issues.append("Missing HttpOnly flag")
        if not any(part.lower().startswith("samesite=") for part in parts[1:]):
            issues.append("Missing SameSite attribute")

        analysis.append(
            {
                "name": cookie_name,
                "issue": ", ".join(issues) if issues else "No obvious attribute gap in exposed header",
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
            summary = "Technology signals were observed, but internal version verification is still needed to confirm maintenance status."
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
