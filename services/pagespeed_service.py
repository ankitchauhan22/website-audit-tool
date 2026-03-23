from __future__ import annotations

import os
import time
from statistics import mean

import requests


PAGESPEED_API_URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
PAGESPEED_CACHE_TTL = 900
_PAGESPEED_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}

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

PERFORMANCE_FACTOR_WEIGHTS = {
    "largest_contentful_paint": 7,
    "cumulative_layout_shift": 5,
    "first_contentful_paint": 3,
    "server_response_time": 4,
    "interaction_responsiveness": 5,
    "image_optimization": 3,
    "javascript_optimization": 3,
    "css_optimization": 3,
    "caching": 1,
    "cdn_usage": 1,
}


def _extract_audit_recommendations(audits: dict) -> list[str]:
    recommendations = []
    candidates = []
    for audit in audits.values():
        score = audit.get("score")
        title = audit.get("title")
        savings_ms = (((audit.get("details") or {}).get("overallSavingsMs")) or 0)
        if title and isinstance(score, (int, float)) and score < 0.9:
            candidates.append((score, savings_ms, title))

    for _, _, title in sorted(candidates, key=lambda item: (item[0], -item[1]))[:3]:
        recommendations.append(title)
    return recommendations


def _numeric_value(audits: dict, audit_id: str):
    return (audits.get(audit_id) or {}).get("numericValue")


def _display_value(audits: dict, audit_id: str, fallback: str = "Not available") -> str:
    return (audits.get(audit_id) or {}).get("displayValue", fallback)


def _audit_score(audits: dict, audit_id: str) -> float | None:
    score = (audits.get(audit_id) or {}).get("score")
    if isinstance(score, (int, float)):
        return max(0.0, min(float(score), 1.0))
    return None


def _threshold_points(value, good_threshold, warning_threshold, points, lower_is_better=True):
    if not isinstance(value, (int, float)):
        return round(points * 0.35, 1)
    if lower_is_better:
        if value <= good_threshold:
            return float(points)
        if value >= warning_threshold:
            return 0.0
        span = warning_threshold - good_threshold
        ratio = (warning_threshold - value) / span if span else 0
        return round(points * ratio, 1)
    if value >= good_threshold:
        return float(points)
    if value <= warning_threshold:
        return 0.0
    span = good_threshold - warning_threshold
    ratio = (value - warning_threshold) / span if span else 0
    return round(points * ratio, 1)


def _metric_factor(name: str, observed: str, benchmark: str, achieved: float, points: int, note: str) -> dict:
    return {
        "name": name,
        "observed": observed,
        "benchmark": benchmark,
        "achieved": round(achieved, 1),
        "points": points,
        "note": note,
    }


def _cdn_signal(assets: list[str], headers: dict) -> tuple[bool, str]:
    header_blob = " ".join(f"{key}:{value}" for key, value in (headers or {}).items()).lower()
    asset_blob = " ".join(assets or []).lower()
    for marker in CDN_MARKERS:
        if marker in header_blob or marker in asset_blob:
            return True, marker
    return False, ""


def _build_factor_breakdown(audits: dict, assets: list[str], headers: dict) -> tuple[list[dict], int]:
    lcp_value = _numeric_value(audits, "largest-contentful-paint")
    cls_value = _numeric_value(audits, "cumulative-layout-shift")
    fcp_value = _numeric_value(audits, "first-contentful-paint")
    ttfb_value = _numeric_value(audits, "server-response-time")
    inp_value = _numeric_value(audits, "interaction-to-next-paint")
    tbt_value = _numeric_value(audits, "total-blocking-time")
    uses_long_cache_score = _audit_score(audits, "uses-long-cache-ttl")
    image_scores = [
        score for score in (
            _audit_score(audits, "modern-image-formats"),
            _audit_score(audits, "uses-optimized-images"),
            _audit_score(audits, "offscreen-images"),
        )
        if score is not None
    ]
    js_scores = [
        score for score in (
            _audit_score(audits, "unused-javascript"),
            _audit_score(audits, "legacy-javascript"),
            _audit_score(audits, "bootup-time"),
        )
        if score is not None
    ]
    css_scores = [
        score for score in (
            _audit_score(audits, "unused-css-rules"),
            _audit_score(audits, "unminified-css"),
            _audit_score(audits, "render-blocking-resources"),
        )
        if score is not None
    ]
    cdn_present, cdn_marker = _cdn_signal(assets, headers)
    caching_header = str((headers or {}).get("Cache-Control", "")).lower()

    factors = []
    factors.append(
        _metric_factor(
            "LCP",
            _display_value(audits, "largest-contentful-paint", "Not measured"),
            "< 2.5s",
            _threshold_points(lcp_value, 2500, 4000, PERFORMANCE_FACTOR_WEIGHTS["largest_contentful_paint"]),
            PERFORMANCE_FACTOR_WEIGHTS["largest_contentful_paint"],
            "Largest Contentful Paint should stay below 2.5 seconds.",
        )
    )
    factors.append(
        _metric_factor(
            "CLS",
            _display_value(audits, "cumulative-layout-shift", "Not measured"),
            "< 0.1",
            _threshold_points(cls_value, 0.1, 0.25, PERFORMANCE_FACTOR_WEIGHTS["cumulative_layout_shift"]),
            PERFORMANCE_FACTOR_WEIGHTS["cumulative_layout_shift"],
            "Cumulative Layout Shift should stay below 0.1.",
        )
    )
    factors.append(
        _metric_factor(
            "FCP",
            _display_value(audits, "first-contentful-paint", "Not measured"),
            "< 1.8s",
            _threshold_points(fcp_value, 1800, 3000, PERFORMANCE_FACTOR_WEIGHTS["first_contentful_paint"]),
            PERFORMANCE_FACTOR_WEIGHTS["first_contentful_paint"],
            "First Contentful Paint should stay below 1.8 seconds.",
        )
    )
    factors.append(
        _metric_factor(
            "TTFB",
            _display_value(audits, "server-response-time", "Not measured"),
            "< 800ms",
            _threshold_points(ttfb_value, 800, 1800, PERFORMANCE_FACTOR_WEIGHTS["server_response_time"]),
            PERFORMANCE_FACTOR_WEIGHTS["server_response_time"],
            "Server response time should stay below 800ms.",
        )
    )

    interaction_observed = (
        _display_value(audits, "interaction-to-next-paint", "")
        if isinstance(inp_value, (int, float))
        else _display_value(audits, "total-blocking-time", "Not measured")
    )
    interaction_benchmark = "< 200ms INP/TBT"
    interaction_points = _threshold_points(
        inp_value if isinstance(inp_value, (int, float)) else tbt_value,
        200,
        500 if isinstance(inp_value, (int, float)) else 600,
        PERFORMANCE_FACTOR_WEIGHTS["interaction_responsiveness"],
    )
    factors.append(
        _metric_factor(
            "INP / TBT",
            interaction_observed or "Not measured",
            interaction_benchmark,
            interaction_points,
            PERFORMANCE_FACTOR_WEIGHTS["interaction_responsiveness"],
            "Interaction responsiveness should stay below 200ms.",
        )
    )

    image_score = round((mean(image_scores) if image_scores else 0.35) * PERFORMANCE_FACTOR_WEIGHTS["image_optimization"], 1)
    factors.append(
        _metric_factor(
            "Image Optimization",
            "Optimized" if image_score >= 2.4 else "Needs work",
            "Modern formats, compression, lazy loading",
            image_score,
            PERFORMANCE_FACTOR_WEIGHTS["image_optimization"],
            "Large image payloads slow rendering and increase mobile LCP.",
        )
    )

    js_score = round((mean(js_scores) if js_scores else 0.35) * PERFORMANCE_FACTOR_WEIGHTS["javascript_optimization"], 1)
    factors.append(
        _metric_factor(
            "JS Optimization",
            "Optimized" if js_score >= 2.4 else "Needs work",
            "Low unused JS, fast boot-up, modern bundle",
            js_score,
            PERFORMANCE_FACTOR_WEIGHTS["javascript_optimization"],
            "Heavy JavaScript affects execution cost and interaction readiness.",
        )
    )

    css_score = round((mean(css_scores) if css_scores else 0.35) * PERFORMANCE_FACTOR_WEIGHTS["css_optimization"], 1)
    factors.append(
        _metric_factor(
            "CSS Optimization",
            "Optimized" if css_score >= 2.4 else "Needs work",
            "Low unused CSS and minimal render blocking",
            css_score,
            PERFORMANCE_FACTOR_WEIGHTS["css_optimization"],
            "Blocking or unused CSS delays first paint.",
        )
    )

    cache_points = PERFORMANCE_FACTOR_WEIGHTS["caching"] if uses_long_cache_score and uses_long_cache_score >= 0.9 else 0.5 if ("max-age" in caching_header or uses_long_cache_score) else 0.0
    factors.append(
        _metric_factor(
            "Caching",
            "Present" if cache_points >= 1 else "Weak or missing",
            "Long-lived cache headers on static assets",
            cache_points,
            PERFORMANCE_FACTOR_WEIGHTS["caching"],
            "Browser caching reduces repeat-visit payload cost.",
        )
    )

    cdn_points = float(PERFORMANCE_FACTOR_WEIGHTS["cdn_usage"]) if cdn_present else 0.0
    factors.append(
        _metric_factor(
            "CDN Usage",
            f"Observed ({cdn_marker})" if cdn_present else "Not clearly exposed",
            "Edge/CDN delivery visible from headers or assets",
            cdn_points,
            PERFORMANCE_FACTOR_WEIGHTS["cdn_usage"],
            "A CDN often improves latency and cache reach for public assets.",
        )
    )

    achieved_total = round(sum(item["achieved"] for item in factors), 1)
    max_points = sum(item["points"] for item in factors)
    benchmark_score = round((achieved_total / max_points) * 100)
    return factors, benchmark_score


def _strategy_payload(url: str, strategy: str, timeout: int, assets: list[str] | None = None, headers: dict | None = None) -> dict:
    cache_key = (url, strategy)
    cached = _PAGESPEED_CACHE.get(cache_key)
    if cached and time.time() - cached[0] < PAGESPEED_CACHE_TTL:
        return cached[1]

    params = {
        "url": url,
        "strategy": strategy,
        "category": "performance",
    }
    api_key = os.getenv("GOOGLE_PAGESPEED_API_KEY", "").strip()
    if api_key:
        params["key"] = api_key

    response = requests.get(
        PAGESPEED_API_URL,
        params=params,
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    lighthouse = payload.get("lighthouseResult") or {}
    category = (lighthouse.get("categories") or {}).get("performance") or {}
    audits = lighthouse.get("audits") or {}
    score = category.get("score")
    benchmark_breakdown, benchmark_score = _build_factor_breakdown(audits, assets or [], headers or {})
    result = {
        "strategy": strategy,
        "score": round(score * 100) if isinstance(score, (int, float)) else None,
        "benchmark_score": benchmark_score,
        "benchmark_breakdown": benchmark_breakdown,
        "largest_contentful_paint": (audits.get("largest-contentful-paint") or {}).get("displayValue", "Not available"),
        "first_contentful_paint": (audits.get("first-contentful-paint") or {}).get("displayValue", "Not available"),
        "cumulative_layout_shift": (audits.get("cumulative-layout-shift") or {}).get("displayValue", "Not available"),
        "interactive": (audits.get("interaction-to-next-paint") or {}).get("displayValue")
        or (audits.get("total-blocking-time") or {}).get("displayValue")
        or (audits.get("interactive") or {}).get("displayValue", "Not available"),
        "time_to_first_byte": (audits.get("server-response-time") or {}).get("displayValue", "Not available"),
        "recommendations": _extract_audit_recommendations(audits),
        "source": "Google PageSpeed Insights",
        "estimated": False,
    }
    _PAGESPEED_CACHE[cache_key] = (time.time(), result)
    return result


def _fallback_strategy_payload(strategy: str, html: str, assets: list[str], headers: dict) -> dict:
    script_count = sum(1 for asset in assets if ".js" in asset.lower())
    style_count = sum(1 for asset in assets if ".css" in asset.lower())
    image_count = sum(1 for asset in assets if any(ext in asset.lower() for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg")))
    html_size_kb = max(len((html or "").encode("utf-8")) // 1024, 1)
    compression_enabled = bool(headers.get("Content-Encoding"))
    caching_enabled = bool(headers.get("Cache-Control"))
    base_score = 82 if strategy == "desktop" else 74
    penalties = 0
    recommendations = []

    if html_size_kb > 180:
        penalties += 8
        recommendations.append("Reduce HTML payload size on the landing page")
    if script_count > 12:
        penalties += 10 if strategy == "mobile" else 8
        recommendations.append("Reduce JavaScript payload and execution cost")
    if style_count > 6:
        penalties += 4
        recommendations.append("Consolidate or defer non-critical CSS")
    if image_count > 20:
        penalties += 6
        recommendations.append("Compress and lazy-load large image sets")
    if not compression_enabled:
        penalties += 10
        recommendations.append("Enable Brotli or gzip compression")
    if not caching_enabled:
        penalties += 6
        recommendations.append("Expose stronger cache-control for static assets")

    benchmark_breakdown = []
    script_count = max(script_count, 1)
    style_count = max(style_count, 1)
    image_count = max(image_count, 1)
    cdn_present, cdn_marker = _cdn_signal(assets, headers)
    compression_label = headers.get("Content-Encoding", "Not exposed")
    cache_label = headers.get("Cache-Control", "Not exposed")
    benchmark_breakdown.append(_metric_factor("LCP", "Estimated from payload", "< 2.5s", 4.5 if html_size_kb < 140 else 2.0, PERFORMANCE_FACTOR_WEIGHTS["largest_contentful_paint"], "Estimated from HTML and asset weight."))
    benchmark_breakdown.append(_metric_factor("CLS", "Not measured passively", "< 0.1", 1.8, PERFORMANCE_FACTOR_WEIGHTS["cumulative_layout_shift"], "Layout shift needs live browser measurement."))
    benchmark_breakdown.append(_metric_factor("FCP", "Estimated from payload", "< 1.8s", 2.0 if style_count <= 4 else 1.0, PERFORMANCE_FACTOR_WEIGHTS["first_contentful_paint"], "Estimated from render-blocking payload size."))
    benchmark_breakdown.append(_metric_factor("TTFB", compression_label, "< 800ms", 2.5 if headers.get("Server-Timing") else 1.5, PERFORMANCE_FACTOR_WEIGHTS["server_response_time"], "Passive mode cannot measure TTFB precisely."))
    benchmark_breakdown.append(_metric_factor("INP / TBT", "Not measured passively", "< 200ms INP/TBT", 2.0 if script_count <= 8 else 0.8, PERFORMANCE_FACTOR_WEIGHTS["interaction_responsiveness"], "Estimated from visible JavaScript weight."))
    benchmark_breakdown.append(_metric_factor("Image Optimization", f"{image_count} image asset(s)", "Modern formats, compression, lazy loading", 2.5 if image_count <= 12 else 1.2, PERFORMANCE_FACTOR_WEIGHTS["image_optimization"], "Passive evidence checks image count and formats only."))
    benchmark_breakdown.append(_metric_factor("JS Optimization", f"{script_count} script asset(s)", "Low unused JS, fast boot-up, modern bundle", 2.5 if script_count <= 8 else 1.0, PERFORMANCE_FACTOR_WEIGHTS["javascript_optimization"], "Passive evidence checks script count only."))
    benchmark_breakdown.append(_metric_factor("CSS Optimization", f"{style_count} stylesheet(s)", "Low unused CSS and minimal render blocking", 2.5 if style_count <= 4 else 1.0, PERFORMANCE_FACTOR_WEIGHTS["css_optimization"], "Passive evidence checks stylesheet count only."))
    benchmark_breakdown.append(_metric_factor("Caching", cache_label, "Long-lived cache headers on static assets", 1.0 if caching_enabled else 0.0, PERFORMANCE_FACTOR_WEIGHTS["caching"], "Derived from public cache headers."))
    benchmark_breakdown.append(_metric_factor("CDN Usage", f"Observed ({cdn_marker})" if cdn_present else "Not clearly exposed", "Edge/CDN delivery visible from headers or assets", 1.0 if cdn_present else 0.0, PERFORMANCE_FACTOR_WEIGHTS["cdn_usage"], "Derived from public headers and asset hosts."))

    benchmark_total = sum(item["achieved"] for item in benchmark_breakdown)
    score = max(base_score - penalties, 35)
    benchmark_score = round((benchmark_total / sum(item["points"] for item in benchmark_breakdown)) * 100)
    return {
        "strategy": strategy,
        "score": score,
        "benchmark_score": benchmark_score,
        "benchmark_breakdown": benchmark_breakdown,
        "largest_contentful_paint": "Estimated from passive evidence",
        "first_contentful_paint": "Estimated from passive evidence",
        "cumulative_layout_shift": "Not measured in fallback mode",
        "interactive": "Estimated from passive evidence",
        "time_to_first_byte": "Not measured in fallback mode",
        "recommendations": recommendations[:3] or ["Run a live Lighthouse audit for precise performance diagnostics"],
        "source": "Passive performance estimate",
        "estimated": True,
    }


def run_pagespeed_audit(url: str, html: str = "", assets: list[str] | None = None, headers: dict | None = None, timeout: int = 25) -> dict:
    """Fetch mobile and desktop PageSpeed summaries from the PSI API, with passive fallback."""
    assets = assets or []
    headers = headers or {}
    try:
        return {
            "mobile": _strategy_payload(url, "mobile", timeout, assets=assets, headers=headers),
            "desktop": _strategy_payload(url, "desktop", timeout, assets=assets, headers=headers),
            "error": None,
            "warning": None,
        }
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        return {
            "mobile": _fallback_strategy_payload("mobile", html, assets, headers),
            "desktop": _fallback_strategy_payload("desktop", html, assets, headers),
            "error": None,
            "warning": (
                "Google PageSpeed Insights was unavailable, so this section is showing a passive performance estimate."
                if status_code == 429
                else f"Google PageSpeed Insights was unavailable ({status_code or 'request error'}), so this section is showing a passive performance estimate."
            ),
        }
    except requests.RequestException as exc:
        return {
            "mobile": _fallback_strategy_payload("mobile", html, assets, headers),
            "desktop": _fallback_strategy_payload("desktop", html, assets, headers),
            "error": None,
            "warning": f"Google PageSpeed Insights was unavailable, so this section is showing a passive performance estimate.",
        }
