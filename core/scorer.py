from __future__ import annotations


def _priority_for(severity: str) -> str:
    mapping = {"must": "P1", "high": "P2", "monitor": "P3", "good": "P4"}
    return mapping.get((severity or "").lower(), "P3")


def _factor(label: str, impact: int, severity: str, detail: str, action: str, category: str) -> dict:
    return {
        "label": label,
        "impact": impact,
        "severity": severity,
        "priority": _priority_for(severity),
        "detail": detail,
        "action": action,
        "category": category,
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


def _security_score(scan: dict) -> tuple[int, list[dict], dict]:
    headers = scan.get("security", [])
    failed_headers = [item for item in headers if item.get("status") == "FAIL"]
    partial_headers = [item for item in headers if item.get("status") == "PARTIAL"]
    cookie_issues = [item for item in scan.get("cookie_issues", []) if item.get("is_insecure")]
    form_reflections = [item for item in scan.get("form_probes", []) if item.get("reflected_input")]
    transport = scan.get("transport", [])
    https = next((item for item in transport if item.get("check") == "HTTPS"), {})
    tls_validation = next((item for item in transport if item.get("check") == "TLS Validation"), {})
    cve_hits = sum(len(item.get("cves", [])) for item in scan.get("libraries", []))
    score = 100
    score -= min(40, len(failed_headers) * 8 + len(partial_headers) * 4)
    score -= min(20, len(cookie_issues) * 5)
    score -= min(10, len(form_reflections) * 10)
    score -= min(15, cve_hits * 5)
    if str(https.get("value", "")).lower() != "enabled":
        score -= 20
    if "failed" in str(tls_validation.get("value", "")).lower():
        score -= 10
    return max(0, score), [], {
        "failed_headers": len(failed_headers),
        "partial_headers": len(partial_headers),
        "cookie_issues": len(cookie_issues),
        "cve_hits": cve_hits,
        "form_reflections": len(form_reflections),
    }


def _performance_score(scan: dict) -> tuple[int, list[dict], dict]:
    performance = scan.get("performance_audit") or {}
    mobile = performance.get("mobile") or {}
    desktop = performance.get("desktop") or {}
    mobile_score = mobile.get("benchmark_score")
    desktop_score = desktop.get("benchmark_score")
    if not isinstance(mobile_score, int):
        mobile_score = mobile.get("score") if isinstance(mobile.get("score"), int) else 50
    if not isinstance(desktop_score, int):
        desktop_score = desktop.get("score") if isinstance(desktop.get("score"), int) else 50
    overall = round((mobile_score * 0.6) + (desktop_score * 0.4))
    return overall, [], {"mobile": mobile_score, "desktop": desktop_score}


def _seo_score(scan: dict) -> tuple[int, list[dict], dict]:
    seo = scan.get("seo_audit") or {}
    return int(seo.get("score", 0)), [], {
        "issues": len(seo.get("issues", []) or []),
        "achieved_points": seo.get("achieved_points", 0),
        "max_points": seo.get("max_points", 35),
    }


def _technology_health_score(scan: dict) -> tuple[int, list[dict], dict]:
    stack = scan.get("technology_stack", []) or []
    outdated = [item for item in stack if item.get("status") in {"Outdated", "Deprecated"}]
    observed = [item for item in stack if item.get("status") == "Observed"]
    cve_hits = sum(len(item.get("cves", [])) for item in scan.get("libraries", []))
    exposed_versions = [
        item for item in (scan.get("libraries", []) + scan.get("plugins", []) + scan.get("modules", []))
        if item.get("detected_version") not in {None, "", "Not publicly exposed"}
    ]
    score = 100
    score -= min(40, len(outdated) * 15)
    score -= min(20, len(observed) * 4)
    score -= min(20, cve_hits * 5)
    score += min(10, len(exposed_versions) * 2)
    return max(0, min(100, score)), [], {
        "outdated": len(outdated),
        "observed_without_lifecycle": len(observed),
        "cve_hits": cve_hits,
        "versioned_components": len(exposed_versions),
    }


def _build_breakdown(scan: dict, seo_score: int, performance_score: int, security_score: int, technology_score: int, meta: dict) -> list[dict]:
    breakdown = [
        _factor(
            "Technology health",
            round((technology_score * 0.20) - 20),
            "good" if technology_score >= 90 else "monitor" if technology_score >= 75 else "high",
            f"{meta['technology']['outdated']} outdated/deprecated item(s), {meta['technology']['cve_hits']} mapped CVE match(es).",
            "Prioritize supported release lines for the detected platform, plugins, modules, and frontend libraries.",
            "Technology",
        ),
        _factor(
            "Security posture",
            round((security_score * 0.30) - 30),
            "good" if security_score >= 90 else "monitor" if security_score >= 75 else "high",
            f"{meta['security']['failed_headers']} failed headers, {meta['security']['cookie_issues']} insecure cookie issue(s), {meta['security']['cve_hits']} mapped CVE match(es).",
            "Fix missing headers, insecure cookie flags, TLS issues, and vulnerable exposed components.",
            "Security",
        ),
        _factor(
            "Performance profile",
            round((performance_score * 0.30) - 30),
            "good" if performance_score >= 90 else "monitor" if performance_score >= 75 else "high",
            f"Mobile {meta['performance']['mobile']}/100 and Desktop {meta['performance']['desktop']}/100 after benchmark normalization.",
            "Improve page weight, request count, caching, images, and JavaScript execution on the weaker profile first.",
            "Performance",
        ),
        _factor(
            "SEO readiness",
            round((seo_score * 0.20) - 20),
            "good" if seo_score >= 90 else "monitor" if seo_score >= 75 else "high",
            f"{meta['seo']['issues']} SEO issue(s) identified across metadata, crawlability, structure, and markup validation.",
            "Fix indexability, metadata, structured data, and content structure issues at the template level.",
            "SEO",
        ),
    ]

    if meta["security"]["failed_headers"]:
        breakdown.append(
            _factor(
                f"{meta['security']['failed_headers']} security headers failed",
                -min(16, meta["security"]["failed_headers"] * 4),
                "must",
                "One or more required response headers were missing from the public response set.",
                "Add strict transport and browser protection headers, then validate production responses again.",
                "Security",
            )
        )
    if meta["technology"]["outdated"]:
        breakdown.append(
            _factor(
                f"{meta['technology']['outdated']} outdated technologies observed",
                -min(20, meta["technology"]["outdated"] * 6),
                "must",
                "The scan found technologies on older or deprecated release lines.",
                "Upgrade the platform and exposed components to supported release lines before remediation items are closed.",
                "Technology",
            )
        )
    if meta["seo"]["issues"]:
        breakdown.append(
            _factor(
                f"{meta['seo']['issues']} SEO issues observed",
                -min(12, max(2, meta["seo"]["issues"] * 2)),
                "high" if meta["seo"]["issues"] >= 3 else "monitor",
                "The public templates still expose SEO issues that affect discoverability or search snippet quality.",
                "Correct metadata, crawl directives, heading structure, structured data, and markup validation issues.",
                "SEO",
            )
        )
    return breakdown


def calculate_audit_scores(scan: dict) -> tuple[int, list[dict], dict, dict]:
    if scan.get("error"):
        breakdown = [
            _factor(
                "Target fetch failed",
                -100,
                "must",
                "The target could not be fetched reliably, so downstream checks were not trustworthy.",
                "Restore reachability, TLS trust, or bot-access compatibility and rerun the audit.",
                "General",
            )
        ]
        return 0, breakdown, {}, {"benchmark_label": "Critical", "weights": {"technology_health": 0.20, "security": 0.30, "performance": 0.30, "seo": 0.20}}

    technology_score, _, technology_meta = _technology_health_score(scan)
    security_score, _, security_meta = _security_score(scan)
    performance_score, _, performance_meta = _performance_score(scan)
    seo_score, _, seo_meta = _seo_score(scan)
    final_score = round((technology_score * 0.20) + (security_score * 0.30) + (performance_score * 0.30) + (seo_score * 0.20))
    meta = {
        "technology": technology_meta,
        "security": security_meta,
        "performance": performance_meta,
        "seo": seo_meta,
    }
    breakdown = _build_breakdown(scan, seo_score, performance_score, security_score, technology_score, meta)
    category_scores = {
        "technology_health": technology_score,
        "security": security_score,
        "performance": performance_score,
        "seo": seo_score,
    }
    score_model = {
        "benchmark_label": _benchmark_label(final_score),
        "weights": {"technology_health": 0.20, "security": 0.30, "performance": 0.30, "seo": 0.20},
        "categories": {
            "technology_health": {"score": technology_score, **technology_meta},
            "security": {"score": security_score, **security_meta},
            "performance": {"score": performance_score, **performance_meta},
            "seo": {"score": seo_score, **seo_meta},
        },
    }
    return final_score, breakdown, category_scores, score_model


def risk_level(score: int) -> str:
    return {
        "Excellent": "Low",
        "Good": "Low",
        "Average": "Medium",
        "Poor": "High",
        "Critical": "High",
    }[_benchmark_label(score)]

