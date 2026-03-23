def _priority_for(severity: str) -> str:
    mapping = {
        "must": "P1",
        "high": "P2",
        "monitor": "P3",
        "good": "P4",
    }
    return mapping.get((severity or "").lower(), "P3")


def _factor(label: str, impact: int, severity: str, detail: str, action: str, category: str | None = None) -> dict:
    return {
        "label": label,
        "impact": impact,
        "severity": severity,
        "priority": _priority_for(severity),
        "detail": detail,
        "action": action,
        "category": category or "General",
    }


def _benchmark_label(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 60:
        return "Average"
    if score >= 40:
        return "Poor"
    return "Critical"


def _security_category_score(scan: dict) -> tuple[int, list[dict], dict]:
    achieved = 0.0
    details = []

    https_item = next((item for item in scan.get("transport", []) if item["check"] == "HTTPS"), None)
    tls_validation = next((item for item in scan.get("transport", []) if item["check"] == "TLS Validation"), None)
    fetch_warning = scan.get("fetch_warning")
    https_points = 5.0 if https_item and https_item["value"] == "Enabled" and not fetch_warning else 3.0 if https_item and https_item["value"] == "Enabled" else 0.0
    achieved += https_points
    details.append({"name": "HTTPS (SSL Valid)", "achieved": https_points, "points": 5})

    headers = scan.get("security", [])
    passed_headers = sum(1 for item in headers if item.get("status") == "PASS")
    header_points = round((passed_headers / max(len(headers), 1)) * 8, 1)
    achieved += header_points
    details.append({"name": "HTTP Security Headers", "achieved": header_points, "points": 8})

    cve_hits = sum(len(item.get("cves", [])) for item in scan.get("libraries", []))
    outdated_stack = sum(1 for item in scan.get("technology_stack", []) if item.get("status") in {"Outdated", "Deprecated"})
    if cve_hits or outdated_stack:
        vulnerability_points = 0.0
    else:
        lookup_attempted = any(item.get("cve_summary") != "No CVE lookup performed" for item in scan.get("libraries", []))
        vulnerability_points = 5.0 if lookup_attempted else 3.0
    achieved += vulnerability_points
    details.append({"name": "Vulnerability Exposure", "achieved": vulnerability_points, "points": 5})

    platform_version = scan.get("version")
    exposed_plugin_versions = sum(
        1 for item in (scan.get("plugins", []) + scan.get("modules", []))
        if item.get("detected_version") not in {None, "", "Not publicly exposed"}
    )
    version_exposure_points = 3.0 if platform_version in {None, "", "Not publicly exposed"} and exposed_plugin_versions == 0 else 1.5 if exposed_plugin_versions <= 1 else 0.0
    achieved += version_exposure_points
    details.append({"name": "CMS/Plugin Version Detection", "achieved": version_exposure_points, "points": 3})

    cookie_issues = [item for item in scan.get("cookie_issues", []) if item.get("is_insecure")]
    cookie_points = 3.0 if not cookie_issues else 1.5 if len(cookie_issues) <= 2 else 0.0
    achieved += cookie_points
    details.append({"name": "Cookie Security", "achieved": cookie_points, "points": 3})

    mixed_content_assets = scan.get("mixed_content_assets", [])
    mixed_points = 2.0 if not mixed_content_assets else 0.0
    achieved += mixed_points
    details.append({"name": "Mixed Content Issues", "achieved": mixed_points, "points": 2})

    stack_names = {item.get("name") for item in scan.get("technology_stack", [])}
    waf_markers = {"Cloudflare", "Akamai", "Fastly", "reCAPTCHA", "Cloudflare Bot Management"}
    waf_points = 2.0 if stack_names & waf_markers else 1.0
    achieved += waf_points
    details.append({"name": "WAF / Protection Layer", "achieved": waf_points, "points": 2})

    reflected_probes = [item for item in scan.get("form_probes", []) if item.get("reflected_input")]
    insecure_session_cookies = [item for item in cookie_issues if item.get("is_session_like")]
    auth_points = 2.0 if not reflected_probes and not insecure_session_cookies else 0.0 if reflected_probes else 1.0
    achieved += auth_points
    details.append({"name": "Authentication Security", "achieved": auth_points, "points": 2})

    score = round((achieved / 30) * 100)
    return score, details, {"achieved_points": round(achieved, 1), "max_points": 30}


def _performance_category_score(scan: dict) -> tuple[int, list[dict], dict]:
    performance = scan.get("performance_audit") or {}
    mobile_audit = performance.get("mobile") or {}
    desktop_audit = performance.get("desktop") or {}
    mobile = mobile_audit.get("benchmark_score")
    desktop = desktop_audit.get("benchmark_score")
    mobile_score = mobile if isinstance(mobile, int) else 50
    desktop_score = desktop if isinstance(desktop, int) else 50
    weighted = round((mobile_score * 0.6) + (desktop_score * 0.4))
    details = [
        {
            "name": "Mobile Performance",
            "achieved": mobile_score,
            "points": 100,
            "breakdown": mobile_audit.get("benchmark_breakdown", []),
        },
        {
            "name": "Desktop Performance",
            "achieved": desktop_score,
            "points": 100,
            "breakdown": desktop_audit.get("benchmark_breakdown", []),
        },
    ]
    return weighted, details, {"mobile": mobile_score, "desktop": desktop_score, "weighting": "Mobile 60% / Desktop 40%"}


def _seo_category_score(scan: dict) -> tuple[int, list[dict], dict]:
    seo = scan.get("seo_audit") or {}
    score = int(seo.get("score", 0))
    details = seo.get("factors", [])
    return score, details, {"achieved_points": seo.get("achieved_points", 0), "max_points": seo.get("max_points", 35)}


def calculate_score(scan):
    if scan.get("error"):
        return 0, [
            _factor(
                "Target fetch failed",
                -100,
                "must",
                "The site could not be fetched reliably, so no downstream checks could be validated.",
                "Restore reachability, TLS trust, or bot-access compatibility, then rerun the audit.",
                category="General",
            )
        ], {}, {"benchmark_label": "Critical", "weights": {"seo": 0.35, "performance": 0.35, "security": 0.30}}

    seo_score, seo_details, seo_meta = _seo_category_score(scan)
    performance_score, performance_details, performance_meta = _performance_category_score(scan)
    security_score, security_details, security_meta = _security_category_score(scan)

    weighted_seo = seo_score * 0.35
    weighted_performance = performance_score * 0.35
    weighted_security = security_score * 0.30
    final_score = round(weighted_seo + weighted_performance + weighted_security)

    category_scores = {
        "seo": seo_score,
        "performance": performance_score,
        "security": security_score,
    }

    breakdown = [
        _factor(
            "SEO category score",
            round(weighted_seo - 35),
            "good" if seo_score >= 90 else "monitor" if seo_score >= 75 else "high",
            f"{seo_meta.get('achieved_points', 0)} of {seo_meta.get('max_points', 35)} SEO points achieved.",
            "Improve metadata, indexability, internal linking, structured data, and validation issues.",
            category="SEO",
        ),
        _factor(
            "Performance category score",
            round(weighted_performance - 35),
            "good" if performance_score >= 90 else "monitor" if performance_score >= 75 else "high",
            f"Mobile {performance_meta.get('mobile', 'NA')}/100, Desktop {performance_meta.get('desktop', 'NA')}/100 using benchmark-based scoring and a 60/40 weighting.",
            "Improve Core Web Vitals, caching, CDN coverage, and image/JS/CSS optimization against the published thresholds.",
            category="Performance",
        ),
        _factor(
            "Security category score",
            round(weighted_security - 30),
            "good" if security_score >= 90 else "monitor" if security_score >= 75 else "high",
            f"{security_meta.get('achieved_points', 0)} of {security_meta.get('max_points', 30)} security points achieved.",
            "Harden transport, headers, cookies, version exposure, and vulnerability posture.",
            category="Security",
        ),
    ]

    failed_headers = [item for item in scan.get("security", []) if item.get("status") == "FAIL"]
    if failed_headers:
        breakdown.append(
            _factor(
                f"{len(failed_headers)} security headers missing",
                -8,
                "must",
                "Missing headers: " + ", ".join(item["header"] for item in failed_headers[:5]),
                "Add the missing response headers and verify them in production responses.",
                category="Security",
            )
        )

    cookie_issues = [item for item in scan.get("cookie_issues", []) if item.get("is_insecure")]
    if cookie_issues:
        breakdown.append(
            _factor(
                f"{len(cookie_issues)} cookie security issues observed",
                -3,
                "must" if any(item.get("is_session_like") for item in cookie_issues) else "high",
                "; ".join(f"{item['name']}: {item['issue']}" for item in cookie_issues[:3]),
                "Harden cookie flags on authentication and session cookies, then confirm with a fresh response capture.",
                category="Security",
            )
        )

    performance = scan.get("performance_audit") or {}
    weak_scores = [
        score for score in [
            (performance.get("mobile") or {}).get("score"),
            (performance.get("desktop") or {}).get("score"),
        ]
        if isinstance(score, int) and score < 75
    ]
    if weak_scores:
        breakdown.append(
            _factor(
                "Page speed needs improvement",
                -6 if any(score < 60 for score in weak_scores) else -3,
                "high" if any(score < 60 for score in weak_scores) else "monitor",
                f"Mobile: {(performance.get('mobile') or {}).get('score', 'NA')}/100, Desktop: {(performance.get('desktop') or {}).get('score', 'NA')}/100.",
                "Prioritize the top Lighthouse opportunities on the weaker device profile and retest after deployment.",
                category="Performance",
            )
        )

    seo_issues = (scan.get("seo_audit") or {}).get("issues", [])
    if seo_issues:
        breakdown.append(
            _factor(
                f"{len(seo_issues)} SEO issues observed",
                -4 if len(seo_issues) >= 3 else -2,
                "high" if len(seo_issues) >= 3 else "monitor",
                "; ".join(seo_issues[:3]),
                "Fix homepage metadata and template-level SEO issues, then validate the same pattern across the public page set.",
                category="SEO",
            )
        )

    score_model = {
        "benchmark_label": _benchmark_label(final_score),
        "weights": {"seo": 0.35, "performance": 0.35, "security": 0.30},
        "categories": {
            "seo": {"score": seo_score, **seo_meta, "details": seo_details},
            "performance": {"score": performance_score, **performance_meta, "details": performance_details},
            "security": {"score": security_score, **security_meta, "details": security_details},
        },
    }

    return final_score, breakdown, category_scores, score_model


def risk_level(score):
    label = _benchmark_label(score)
    mapping = {
        "Excellent": "Low",
        "Good": "Low",
        "Average": "Medium",
        "Poor": "High",
        "Critical": "High",
    }
    return mapping[label]
