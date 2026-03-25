from __future__ import annotations

import os
import time

import requests


GTMETRIX_BASE_URL = "https://gtmetrix.com/api/2.0"
PINGDOM_DEFAULT_URL = "https://api.pingdom.com/api/3.1/summary.performance"
PERFORMANCE_CACHE_TTL = 1800
_PERFORMANCE_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}

CDN_MARKERS = (
    "cloudflare",
    "cloudfront",
    "fastly",
    "akamai",
    "cdn",
    "jsdelivr",
    "bootstrapcdn",
    "unpkg",
    "cdnjs",
)


def _format_ms(value) -> str:
    if not isinstance(value, (int, float)):
        return "Not detected"
    if value >= 1000:
        return f"{value / 1000:.2f}s"
    return f"{int(round(value))}ms"


def _format_bytes(value) -> str:
    if not isinstance(value, (int, float)):
        return "Not detected"
    units = ["B", "KB", "MB", "GB"]
    size = float(value)
    unit_index = 0
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    precision = 0 if unit_index == 0 else 2
    return f"{size:.{precision}f} {units[unit_index]}"


def _cache_get(url: str, profile: str) -> dict | None:
    cached = _PERFORMANCE_CACHE.get((url, profile))
    if cached and time.time() - cached[0] < PERFORMANCE_CACHE_TTL:
        return cached[1]
    return None


def _cache_put(url: str, profile: str, payload: dict) -> dict:
    _PERFORMANCE_CACHE[(url, profile)] = (time.time(), payload)
    return payload


def _opportunity(label: str, impact: str, detail: str) -> dict:
    return {"label": label, "impact": impact, "detail": detail}


def _diagnostic(label: str, value: str, detail: str) -> dict:
    return {"label": label, "value": value, "detail": detail}


def _cdn_signal(assets: list[str], headers: dict) -> tuple[bool, str]:
    header_blob = " ".join(f"{key}:{value}" for key, value in (headers or {}).items()).lower()
    asset_blob = " ".join(assets or []).lower()
    for marker in CDN_MARKERS:
        if marker in header_blob or marker in asset_blob:
            return True, marker
    return False, ""


def _build_heuristic_profile(strategy: str, html: str, assets: list[str], headers: dict, warning: str | None = None) -> dict:
    script_count = sum(1 for asset in assets if ".js" in asset.lower())
    style_count = sum(1 for asset in assets if ".css" in asset.lower())
    image_count = sum(1 for asset in assets if any(ext in asset.lower() for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".avif")))
    request_count = max(len(assets), 1)
    page_bytes = len((html or "").encode("utf-8")) + (request_count * 24000)
    compression_enabled = bool(headers.get("Content-Encoding"))
    caching_enabled = bool(headers.get("Cache-Control"))
    cdn_present, cdn_marker = _cdn_signal(assets, headers)

    base_score = 86 if strategy == "desktop" else 72
    penalties = 0
    opportunities = []

    if page_bytes > 2_000_000:
        penalties += 14
        opportunities.append(_opportunity("Reduce page weight", "High", "Large transfer size is likely slowing first and repeat visits."))
    elif page_bytes > 1_000_000:
        penalties += 8

    if request_count > 80:
        penalties += 10
        opportunities.append(_opportunity("Reduce request count", "High", "High request volume increases connection and waterfall overhead."))
    elif request_count > 45:
        penalties += 5

    if script_count > 16:
        penalties += 10 if strategy == "mobile" else 8
        opportunities.append(_opportunity("Reduce JavaScript execution", "High", "Heavy JavaScript increases main-thread work and blocking time."))
    elif script_count > 10:
        penalties += 5

    if image_count > 24:
        penalties += 7
        opportunities.append(_opportunity("Optimize image payloads", "Medium", "Large image inventory should be compressed, modernized, and lazy-loaded."))
    elif image_count > 12:
        penalties += 4

    if style_count > 6:
        penalties += 5
        opportunities.append(_opportunity("Reduce render-blocking CSS", "Medium", "Too many stylesheets can delay first render."))

    if not compression_enabled:
        penalties += 8
        opportunities.append(_opportunity("Enable compression", "High", "Responses should expose gzip or Brotli compression."))
    if not caching_enabled:
        penalties += 6
        opportunities.append(_opportunity("Strengthen caching", "Medium", "Static assets should expose stronger cache directives."))

    if strategy == "mobile":
        penalties += 6

    score = max(base_score - penalties, 25)
    performance_score = max(score - 4, 20)
    structure_score = min(score + 6, 95)

    profile = {
        "strategy": strategy,
        "provider": "heuristic",
        "source": "Estimated Performance Score (API unavailable)",
        "estimated": True,
        "score": score,
        "benchmark_score": score,
        "performance_score": performance_score,
        "structure_score": structure_score,
        "gtmetrix_grade": "Estimated",
        "fully_loaded_time": _format_ms(3600 + (request_count * 35) + (script_count * 18)),
        "total_page_size": _format_bytes(page_bytes),
        "total_requests": request_count,
        "time_to_first_byte": _format_ms(600 if compression_enabled else 900),
        "largest_contentful_paint": _format_ms(2400 + (image_count * 50) + (0 if cdn_present else 350)),
        "cumulative_layout_shift": "Not measured in fallback mode",
        "first_contentful_paint": _format_ms(1500 + (style_count * 80)),
        "interactive": _format_ms(180 + (script_count * 30)),
        "opportunities": opportunities[:4] or [_opportunity("Run live performance testing", "Medium", "Enable GTmetrix to replace this estimate with real browser-based results.")],
        "diagnostics": [
            _diagnostic("Page Weight Impact", _format_bytes(page_bytes), "Estimated from HTML size and request volume."),
            _diagnostic("JS Execution Impact", f"{script_count} script asset(s)", "Estimated from visible script count."),
            _diagnostic("Image Optimization", f"{image_count} image asset(s)", "Estimated from visible image volume and formats."),
            _diagnostic("Caching Efficiency", headers.get("Cache-Control", "Not exposed"), "Derived from the landing page response headers."),
            _diagnostic("CDN Usage", f"Observed ({cdn_marker})" if cdn_present else "Not clearly exposed", "Derived from public headers and asset hosts."),
        ],
        "recommendations": [item["label"] for item in opportunities[:3]],
    }
    if warning:
        profile["warning"] = warning
    return profile


def _gtmetrix_session(api_key: str) -> requests.Session:
    session = requests.Session()
    session.auth = (api_key, "")
    session.headers.update({
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
    })
    return session


def _gtmetrix_profile_config(strategy: str) -> dict:
    upper = strategy.upper()
    config = {
        "location": os.getenv(f"GTMETRIX_{upper}_LOCATION", "").strip(),
        "browser": os.getenv(f"GTMETRIX_{upper}_BROWSER", "").strip(),
        "device": os.getenv(f"GTMETRIX_{upper}_DEVICE", "").strip(),
    }
    if strategy == "mobile" and not any(config.values()):
        return {}
    return {key: value for key, value in config.items() if value}


def _start_gtmetrix_test(session: requests.Session, url: str, strategy: str, timeout: int) -> str:
    attributes = {
        "url": url,
        "report": "lighthouse",
    }
    attributes.update(_gtmetrix_profile_config(strategy))
    response = session.post(
        f"{GTMETRIX_BASE_URL}/tests",
        json={"data": {"type": "test", "attributes": attributes}},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    link = response.headers.get("Location") or (((payload.get("links") or {}).get("self")) or "")
    if not link:
        raise RuntimeError("GTmetrix did not return a test poll URL.")
    if link.startswith("http"):
        return link
    return f"https://gtmetrix.com{link}"


def _poll_gtmetrix_test(session: requests.Session, poll_url: str, timeout: int, max_polls: int = 20) -> str:
    for _ in range(max_polls):
        response = session.get(poll_url, timeout=timeout, allow_redirects=False)
        if response.status_code == 303:
            location = response.headers.get("Location") or ""
            return location if location.startswith("http") else f"https://gtmetrix.com{location}"
        response.raise_for_status()
        payload = response.json()
        attributes = ((payload.get("data") or {}).get("attributes") or {})
        state = attributes.get("state")
        if state == "completed":
            report_url = (((payload.get("data") or {}).get("links") or {}).get("report")) or response.headers.get("Location") or ""
            if report_url:
                return report_url if report_url.startswith("http") else f"https://gtmetrix.com{report_url}"
        if state == "error":
            raise RuntimeError(attributes.get("error") or "GTmetrix test finished with an error state.")
        retry_after = response.headers.get("Retry-After")
        sleep_seconds = int(retry_after) if retry_after and retry_after.isdigit() else 3
        time.sleep(sleep_seconds)
    raise RuntimeError("GTmetrix test polling timed out before the report was ready.")


def _fetch_gtmetrix_json(session: requests.Session, url: str, timeout: int) -> dict:
    response = session.get(url, timeout=timeout)
    response.raise_for_status()
    return response.json()


def _extract_gtmetrix_opportunities(lighthouse_payload: dict) -> tuple[list[dict], list[dict]]:
    audits = ((lighthouse_payload.get("audits") or {}) if isinstance(lighthouse_payload, dict) else {})
    opportunities = []
    diagnostics = []
    audit_map = {
        "uses-optimized-images": "Optimize images",
        "modern-image-formats": "Serve modern image formats",
        "offscreen-images": "Lazy-load offscreen images",
        "unused-javascript": "Reduce unused JavaScript",
        "legacy-javascript": "Avoid legacy JavaScript",
        "bootup-time": "Reduce JS execution time",
        "unused-css-rules": "Reduce unused CSS",
        "render-blocking-resources": "Reduce render-blocking resources",
        "uses-long-cache-ttl": "Strengthen static caching",
    }
    for audit_id, label in audit_map.items():
        audit = audits.get(audit_id) or {}
        score = audit.get("score")
        impact_score = audit.get("_impactScore")
        if isinstance(score, (int, float)) and score >= 0.9:
            continue
        detail = audit.get("description") or audit.get("displayValue") or "Review this GTmetrix audit in the full report."
        impact = "High" if isinstance(impact_score, (int, float)) and impact_score >= 0.48 else "Medium" if isinstance(impact_score, (int, float)) and impact_score >= 0.24 else "Low"
        if score is not None:
            opportunities.append(_opportunity(label, impact, detail))

    diagnostic_ids = {
        "uses-long-cache-ttl": "Caching Efficiency",
        "bootup-time": "JS Execution Impact",
        "render-blocking-resources": "CSS Blocking Impact",
        "offscreen-images": "Image Loading Impact",
    }
    for audit_id, label in diagnostic_ids.items():
        audit = audits.get(audit_id) or {}
        observed = audit.get("displayValue") or "Not detected"
        detail = audit.get("description") or "Reported by GTmetrix."
        diagnostics.append(_diagnostic(label, observed, detail))
    return opportunities[:5], diagnostics


def _normalize_gtmetrix_report(strategy: str, report_payload: dict, lighthouse_payload: dict, assets: list[str], headers: dict) -> dict:
    data = report_payload.get("data") or {}
    attributes = data.get("attributes") or {}
    links = data.get("links") or {}
    audits = (lighthouse_payload or {}).get("audits") or {}
    cdn_present, cdn_marker = _cdn_signal(assets, headers)

    performance_score = attributes.get("performance_score")
    structure_score = attributes.get("structure_score")
    combined_score = round((performance_score * 0.6) + (structure_score * 0.4)) if isinstance(performance_score, (int, float)) and isinstance(structure_score, (int, float)) else attributes.get("gtmetrix_score")

    ttfb_ms = (audits.get("server-response-time") or {}).get("numericValue")
    lcp_ms = (audits.get("largest-contentful-paint") or {}).get("numericValue")
    fcp_ms = (audits.get("first-contentful-paint") or {}).get("numericValue")
    tbt_ms = (audits.get("total-blocking-time") or {}).get("numericValue")
    cls_value = attributes.get("cumulative_layout_shift")
    fully_loaded_time = attributes.get("fully_loaded_time") or attributes.get("fully_loaded_timing")

    opportunities, diagnostics = _extract_gtmetrix_opportunities(lighthouse_payload)
    diagnostics.extend(
        [
            _diagnostic("Page Weight Impact", _format_bytes(attributes.get("page_bytes")), "Reported by GTmetrix from the completed page load."),
            _diagnostic("Total Requests", str(attributes.get("page_requests", "Not detected")), "Reported by GTmetrix from the completed page load."),
            _diagnostic("CDN Usage", f"Observed ({cdn_marker})" if cdn_present else "Not clearly exposed", "Derived from public headers and asset hosts."),
        ]
    )

    return {
        "strategy": strategy,
        "provider": "gtmetrix",
        "source": "GTmetrix API",
        "estimated": False,
        "score": combined_score if isinstance(combined_score, int) else None,
        "benchmark_score": combined_score if isinstance(combined_score, int) else None,
        "performance_score": performance_score,
        "structure_score": structure_score,
        "gtmetrix_score": attributes.get("gtmetrix_score"),
        "gtmetrix_grade": attributes.get("gtmetrix_grade", "Not detected"),
        "fully_loaded_time": _format_ms(fully_loaded_time),
        "total_page_size": _format_bytes(attributes.get("page_bytes")),
        "total_requests": attributes.get("page_requests", "Not detected"),
        "time_to_first_byte": _format_ms(ttfb_ms if isinstance(ttfb_ms, (int, float)) else attributes.get("backend_duration")),
        "largest_contentful_paint": _format_ms(lcp_ms) if isinstance(lcp_ms, (int, float)) else "Not detected",
        "cumulative_layout_shift": f"{cls_value:.3f}" if isinstance(cls_value, (int, float)) else "Not detected",
        "first_contentful_paint": _format_ms(fcp_ms) if isinstance(fcp_ms, (int, float)) else "Not detected",
        "interactive": _format_ms(tbt_ms) if isinstance(tbt_ms, (int, float)) else "Not detected",
        "opportunities": opportunities,
        "diagnostics": diagnostics[:6],
        "recommendations": [item["label"] for item in opportunities[:3]],
        "report_url": links.get("report_url"),
    }


def _run_gtmetrix_profile(url: str, strategy: str, timeout: int, assets: list[str], headers: dict) -> dict:
    cached = _cache_get(url, f"gtmetrix:{strategy}")
    if cached:
        return cached

    api_key = os.getenv("GTMETRIX_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GTmetrix API key is not configured.")

    if strategy == "mobile" and not _gtmetrix_profile_config("mobile"):
        raise RuntimeError("GTmetrix mobile profile is not configured.")

    session = _gtmetrix_session(api_key)
    poll_url = _start_gtmetrix_test(session, url, strategy, timeout)
    report_url = _poll_gtmetrix_test(session, poll_url, timeout)
    report_payload = _fetch_gtmetrix_json(session, report_url, timeout)
    lighthouse_url = (((report_payload.get("data") or {}).get("links") or {}).get("lighthouse")) or ""
    lighthouse_payload = _fetch_gtmetrix_json(session, lighthouse_url, timeout) if lighthouse_url else {}
    return _cache_put(url, f"gtmetrix:{strategy}", _normalize_gtmetrix_report(strategy, report_payload, lighthouse_payload, assets, headers))


def _run_pingdom_profile(url: str, strategy: str, timeout: int) -> dict:
    api_token = os.getenv("PINGDOM_API_TOKEN", "").strip()
    check_id = os.getenv(f"PINGDOM_{strategy.upper()}_CHECK_ID", "").strip()
    if not api_token or not check_id:
        raise RuntimeError("Pingdom fallback is not configured.")

    pingdom_url = os.getenv("PINGDOM_API_URL", PINGDOM_DEFAULT_URL).strip()
    response = requests.get(
        pingdom_url,
        params={"checkid": check_id, "includeuptime": "true"},
        headers={"Authorization": f"Bearer {api_token}"},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    summary = payload.get("summary") or payload.get("performance") or payload
    load_time = summary.get("avgresponse") or summary.get("loadtime")
    page_size = summary.get("pagesize")
    requests_count = summary.get("requests")
    performance_grade = summary.get("grade") or summary.get("performance")
    score = int(performance_grade) if isinstance(performance_grade, (int, float)) else None
    if score is None:
        raise RuntimeError("Pingdom response did not include a usable performance grade.")
    return {
        "strategy": strategy,
        "provider": "pingdom",
        "source": "Pingdom API",
        "estimated": False,
        "score": score,
        "benchmark_score": score,
        "performance_score": score,
        "structure_score": score,
        "gtmetrix_score": None,
        "gtmetrix_grade": "Pingdom",
        "fully_loaded_time": _format_ms(load_time),
        "total_page_size": _format_bytes(page_size),
        "total_requests": requests_count or "Not detected",
        "time_to_first_byte": "Not detected",
        "largest_contentful_paint": "Not detected",
        "cumulative_layout_shift": "Not detected",
        "first_contentful_paint": "Not detected",
        "interactive": "Not detected",
        "opportunities": [],
        "diagnostics": [_diagnostic("Fallback Provider", "Pingdom", "Used because GTmetrix was unavailable for this scan.")],
        "recommendations": [],
    }


def run_pagespeed_audit(url: str, html: str = "", assets: list[str] | None = None, headers: dict | None = None, timeout: int = 30) -> dict:
    """Run GTmetrix-backed performance analysis with Pingdom and heuristic fallbacks."""
    assets = assets or []
    headers = headers or {}
    warnings = []
    profiles = {}

    for strategy in ("desktop", "mobile"):
        try:
            profiles[strategy] = _run_gtmetrix_profile(url, strategy, timeout, assets, headers)
            continue
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            warnings.append(f"GTmetrix {strategy} test was unavailable ({status_code or 'request error'}).")
        except (requests.RequestException, RuntimeError) as exc:
            warnings.append(f"GTmetrix {strategy} test was unavailable: {exc}")

        try:
            profiles[strategy] = _run_pingdom_profile(url, strategy, timeout)
            warnings.append(f"Pingdom fallback was used for the {strategy} profile.")
            continue
        except (requests.RequestException, RuntimeError):
            pass

        profiles[strategy] = _build_heuristic_profile(
            strategy,
            html,
            assets,
            headers,
            warning="Estimated Performance Score (API unavailable)",
        )

    warning_text = " ".join(dict.fromkeys(warnings)) if warnings else None
    if profiles.get("desktop", {}).get("provider") == "heuristic" or profiles.get("mobile", {}).get("provider") == "heuristic":
        warning_text = (
            f"{warning_text} Estimated Performance Score (API unavailable)." if warning_text else "Estimated Performance Score (API unavailable)."
        )

    return {
        "desktop": profiles.get("desktop"),
        "mobile": profiles.get("mobile"),
        "error": None,
        "warning": warning_text,
        "provider": "gtmetrix" if any((profiles.get(item) or {}).get("provider") == "gtmetrix" for item in ("desktop", "mobile")) else "fallback",
    }
