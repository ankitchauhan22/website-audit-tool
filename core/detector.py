from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from core.collector import CollectedEvidence
from detectors.technology_matcher import run_fingerprint_scan


RULE_PATH = Path(__file__).resolve().parent.parent / "data" / "technologies.json"
LEGACY_PATTERN_PATH = Path(__file__).resolve().parent.parent / "detectors" / "data" / "technology_patterns.json"

SOURCE_WEIGHTS = {
    "headers": 4.0,
    "js": 3.0,
    "script": 2.0,
    "html": 2.0,
    "meta": 2.5,
    "url": 2.0,
    "cookies": 1.0,
    "endpoint": 3.0,
    "dns": 2.0,
}

SOURCE_LABELS = {
    "headers": "header",
    "js": "js",
    "script": "asset",
    "html": "html",
    "meta": "meta",
    "url": "url",
    "cookies": "cookie",
    "endpoint": "endpoint",
    "dns": "dns",
}

CATEGORY_PRIORITY = {
    "CMS": 6,
    "Commerce": 5,
    "Headless CMS": 5,
    "Framework": 4,
    "Frontend": 4,
    "Hosting": 3,
    "CDN": 3,
    "Analytics": 2,
    "Marketing": 2,
    "Tag Manager": 2,
    "JavaScript Library": 1,
    "Technology": 1,
}


def _normalize_patterns(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


@lru_cache(maxsize=1)
def _load_rule_data() -> dict:
    if not RULE_PATH.exists():
        return {"technologies": []}
    return json.loads(RULE_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _load_legacy_categories() -> dict[str, list[str]]:
    if not LEGACY_PATTERN_PATH.exists():
        return {}
    payload = json.loads(LEGACY_PATTERN_PATH.read_text(encoding="utf-8"))
    apps = payload.get("apps", {})
    categories = payload.get("categories", {})
    mapped = {}
    aliases = {
        "cms": "CMS",
        "blogs": "Blogs",
        "ecommerce": "Commerce",
        "analytics": "Analytics",
        "tag-managers": "Tag Manager",
        "javascript-frameworks": "JavaScript Library",
        "web-servers": "Hosting",
    }
    for name, app in apps.items():
        values = []
        for category_id in app.get("cats", []):
            raw = categories.get(str(category_id), "")
            values.append(aliases.get(raw, raw.title() if raw else "Technology"))
        if values:
            mapped[name] = values
    return mapped


def _parse_pattern_spec(spec: str) -> tuple[str, str | None]:
    normalized = spec.replace(r"\;version:", ";version:")
    version_group = None
    if ";version:" in normalized:
        normalized, version_group = normalized.split(";version:", 1)
        version_group = version_group.strip()
    return normalized, version_group


def _extract_version(match: re.Match, version_spec: str | None) -> str:
    if not version_spec:
        return "Not publicly exposed"
    if version_spec.startswith("\\"):
        try:
            return match.group(int(version_spec[1:])) or "Not publicly exposed"
        except (ValueError, IndexError):
            return "Not publicly exposed"
    return version_spec or "Not publicly exposed"


def _collect_matches(source: str, patterns, haystack: str, signal_name: str) -> list[dict]:
    matches = []
    for spec in _normalize_patterns(patterns):
        pattern, version_spec = _parse_pattern_spec(spec)
        match = re.search(pattern, haystack or "", re.IGNORECASE)
        if not match:
            continue
        matches.append(
            {
                "type": source,
                "signal": signal_name,
                "confidence": SOURCE_WEIGHTS[source],
                "evidence": f"{SOURCE_LABELS.get(source, source)}:{signal_name} -> {(match.group(0) or '').strip()[:140]}",
                "version": _extract_version(match, version_spec),
            }
        )
    return matches


def _evaluate_rule(rule: dict, evidence: CollectedEvidence) -> dict | None:
    matched_signals = []
    signal_types = set()
    distinct_signal_names = set()

    source_map = {
        "url": evidence.url,
        "html": "\n".join(filter(None, [evidence.html, evidence.rendered_html])),
        "meta": evidence.meta_generator,
        "script": "\n".join(evidence.assets),
        "cookies": "\n".join(evidence.cookies + evidence.set_cookie_headers),
        "js": "\n".join(evidence.js_globals),
        "dns": evidence.headers.get("Server", ""),
    }

    for source_name, rules in (rule.get("signals") or {}).items():
        if source_name == "headers":
            for header_name, patterns in (rules or {}).items():
                header_value = evidence.headers.get(header_name) or evidence.headers.get(header_name.lower()) or ""
                local_matches = _collect_matches("headers", patterns, header_value, header_name)
                if local_matches:
                    signal_types.add("headers")
                    distinct_signal_names.add(f"headers:{header_name}")
                    matched_signals.extend(local_matches)
            continue

        if source_name == "endpoint":
            for endpoint_path, endpoint_rules in (rules or {}).items():
                endpoint_info = evidence.endpoint_results.get(endpoint_path) or {}
                if not endpoint_info.get("ok"):
                    continue
                body = "\n".join(
                    [endpoint_info.get("body", ""), json.dumps(endpoint_info.get("headers", {}), ensure_ascii=True)]
                )
                local_matches = _collect_matches("endpoint", endpoint_rules, body, endpoint_path)
                if local_matches:
                    signal_types.add("endpoint")
                    distinct_signal_names.add(f"endpoint:{endpoint_path}")
                    matched_signals.extend(local_matches)
            continue

        haystack = source_map.get(source_name, "")
        local_matches = _collect_matches(source_name, rules, haystack, source_name)
        if local_matches:
            signal_types.add(source_name)
            distinct_signal_names.add(source_name)
            matched_signals.extend(local_matches)

    if not matched_signals:
        return None

    threshold = float(rule.get("confidence_threshold", 3.5))
    raw_score = sum(item["confidence"] for item in matched_signals)
    diversity_bonus = max(0.0, (len(signal_types) - 1) * 0.5)
    score = min(10.0, round(raw_score + diversity_bonus, 1))
    if score < threshold:
        return None

    version = next(
        (item["version"] for item in matched_signals if item["version"] not in {"", "Not publicly exposed", None}),
        "Not publicly exposed",
    )
    categories = rule.get("categories") or ["Technology"]

    return {
        "name": rule["name"],
        "category": categories[0],
        "categories": categories,
        "confidence_score": score,
        "confidence": "High" if score >= 7.0 and len(signal_types) >= 2 else "Medium" if score >= 5 else "Low",
        "signals": [item["evidence"] for item in matched_signals[:6]],
        "signal_details": matched_signals[:6],
        "signal_types": sorted(signal_types),
        "signal_count": len(distinct_signal_names),
        "detected_version": version,
        "source": "public",
    }


def _merge_legacy_findings(findings: dict[str, dict], evidence: CollectedEvidence) -> dict[str, dict]:
    legacy_categories = _load_legacy_categories()
    for item in run_fingerprint_scan(
        evidence.url,
        evidence.html,
        evidence.headers,
        evidence.meta_generator,
        evidence.assets,
        evidence.cookies,
    ):
        name = item["name"]
        existing = findings.get(name)
        normalized_score = round(min(10.0, item.get("confidence_score", 0) / 10), 1)
        legacy_entry = {
            "name": name,
            "category": (item.get("categories") or legacy_categories.get(name) or ["Technology"])[0],
            "categories": item.get("categories") or legacy_categories.get(name) or ["Technology"],
            "confidence_score": normalized_score,
            "confidence": "High" if normalized_score >= 7.0 else "Medium" if normalized_score >= 5 else "Low",
            "signals": [signal.get("evidence", "") for signal in item.get("signals", [])[:4]],
            "signal_details": [
                {
                    "type": signal.get("source", "html"),
                    "signal": signal.get("source", "pattern"),
                    "confidence": round(min(4.0, signal.get("confidence", 20) / 10), 1),
                    "evidence": signal.get("evidence", ""),
                    "version": signal.get("version", "Not publicly exposed"),
                }
                for signal in item.get("signals", [])[:4]
            ],
            "signal_types": sorted({signal.get("source", "html") for signal in item.get("signals", [])[:4]}),
            "signal_count": len({signal.get("source", "html") for signal in item.get("signals", [])[:4]}),
            "detected_version": item.get("detected_version", "Not publicly exposed"),
            "source": "public",
        }
        if not existing:
            findings[name] = legacy_entry
            continue

        if legacy_entry["confidence_score"] > existing["confidence_score"]:
            merged = {**existing, **legacy_entry}
        else:
            merged = dict(existing)
        merged["signals"] = list(dict.fromkeys((existing.get("signals") or []) + (legacy_entry.get("signals") or [])))[:6]
        merged["signal_types"] = sorted(set(existing.get("signal_types") or []) | set(legacy_entry.get("signal_types") or []))
        merged["signal_count"] = max(existing.get("signal_count", 0), legacy_entry.get("signal_count", 0), len(merged["signal_types"]))
        if merged.get("detected_version") in {"", None, "Not publicly exposed"}:
            merged["detected_version"] = legacy_entry.get("detected_version", "Not publicly exposed")
        merged["confidence_score"] = round(
            min(10.0, max(existing.get("confidence_score", 0), legacy_entry.get("confidence_score", 0)) + max(0, len(merged["signal_types"]) - 1) * 0.2),
            1,
        )
        merged["confidence"] = "High" if merged["confidence_score"] >= 7.0 and len(merged["signal_types"]) >= 2 else "Medium" if merged["confidence_score"] >= 5 else "Low"
        findings[name] = merged
    return findings


def detect_technology_profile(evidence: CollectedEvidence) -> dict:
    findings: dict[str, dict] = {}
    rules = _load_rule_data().get("technologies", [])
    for rule in rules:
        result = _evaluate_rule(rule, evidence)
        if result:
            findings[result["name"]] = result

    findings = _merge_legacy_findings(findings, evidence)
    technologies = sorted(
        findings.values(),
        key=lambda item: (
            -item["confidence_score"],
            -CATEGORY_PRIORITY.get(item["category"], 0),
            -item.get("signal_count", 0),
            item["name"].lower(),
        ),
    )

    cms_candidates = [item for item in technologies if item["category"] in {"CMS", "Commerce", "Headless CMS"}]
    primary_platform = cms_candidates[0] if cms_candidates else (technologies[0] if technologies else None)
    secondary_platforms = [item for item in cms_candidates[1:3]]

    return {
        "technologies": technologies,
        "by_name": {item["name"]: item for item in technologies},
        "endpoint_probes": evidence.endpoint_results,
        "primary_platform": primary_platform,
        "secondary_platforms": secondary_platforms,
    }
