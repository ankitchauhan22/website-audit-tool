import os
import re
from urllib.parse import quote, urlparse

import certifi
import requests


TECHNOLOGYCHECKER_API_TEMPLATE = os.getenv(
    "TECHNOLOGYCHECKER_API_URL",
    "https://technologychecker.io/api/domain/{domain}",
)
TECHNOLOGYCHECKER_TIMEOUT = int(os.getenv("TECHNOLOGYCHECKER_TIMEOUT", "8"))

CMS_CATEGORY_TOKENS = {"cms", "content management", "headless cms", "website builder"}
PLUGIN_CATEGORY_TOKENS = {"plugin", "wordpress plugin", "extension", "module", "addon"}
LIBRARY_CATEGORY_TOKENS = {"javascript library", "js library", "library", "ui framework"}
FRAMEWORK_CATEGORY_TOKENS = {"framework", "javascript framework", "php framework", "frontend framework"}

NAME_ALIASES = {
    "wordpress seo": "Yoast SEO",
    "yoast": "Yoast SEO",
    "yoast seo": "Yoast SEO",
    "wp fastest cache": "WP Fastest Cache",
    "wordfence login security": "Wordfence Login Security",
    "jquery": "jQuery",
    "jquery ui": "jQuery UI",
    "core js": "core-js",
    "undersore js": "Underscore.js",
    "underscore js": "Underscore.js",
    "clipboard js": "Clipboard.js",
    "vue js": "Vue.js",
}


def _safe_domain(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower().removeprefix("www.")


def _canonical_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def _normalize_name(name: str) -> str:
    cleaned = (name or "").strip()
    if not cleaned:
        return ""
    cleaned = re.sub(r"\s+", " ", cleaned)
    alias = NAME_ALIASES.get(cleaned.lower())
    if alias:
        return alias
    return cleaned


def _normalize_version(version) -> str:
    candidate = str(version or "").strip()
    if not candidate:
        return "Not publicly exposed"
    if not re.search(r"\d+\.\d+", candidate):
        return "Not publicly exposed"
    return candidate


def _coerce_confidence(item: dict) -> str:
    value = str(
        item.get("confidence")
        or item.get("confidenceText")
        or item.get("certainty")
        or "Low"
    ).strip().lower()
    if value in {"high", "medium", "low"}:
        return value.title()
    numeric_match = re.search(r"\d+", value)
    if numeric_match:
        score = int(numeric_match.group(0))
        if score >= 80:
            return "High"
        if score >= 50:
            return "Medium"
    return "Low"


def _item_category(item: dict) -> str:
    parts = [
        item.get("category"),
        item.get("categories"),
        item.get("group"),
        item.get("type"),
        item.get("parentCategory"),
    ]
    flattened = " ".join(
        value if isinstance(value, str) else " ".join(str(entry) for entry in value or [])
        for value in parts
        if value
    ).lower()
    if any(token in flattened for token in CMS_CATEGORY_TOKENS):
        return "cms"
    if any(token in flattened for token in PLUGIN_CATEGORY_TOKENS):
        return "plugin"
    if any(token in flattened for token in LIBRARY_CATEGORY_TOKENS):
        return "library"
    if any(token in flattened for token in FRAMEWORK_CATEGORY_TOKENS):
        return "framework"
    return "other"


def _walk_items(payload):
    if isinstance(payload, list):
        for item in payload:
            yield from _walk_items(item)
        return
    if not isinstance(payload, dict):
        return

    if any(key in payload for key in ("name", "technology", "title")):
        yield payload

    for key in ("data", "result", "results", "technologies", "apps", "items", "detections", "categories"):
        value = payload.get(key)
        if value:
            yield from _walk_items(value)


def fetch_external_technology_enrichment(url: str) -> dict:
    domain = _safe_domain(url)
    if not domain:
        return {"available": False, "source": "technologychecker.io", "cms": [], "libraries": [], "plugins": [], "frameworks": []}

    request_url = TECHNOLOGYCHECKER_API_TEMPLATE.format(domain=quote(domain, safe=""))
    headers = {"Accept": "application/json"}
    api_key = os.getenv("TECHNOLOGYCHECKER_API_KEY", "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        headers["X-API-Key"] = api_key

    try:
        response = requests.get(request_url, headers=headers, timeout=TECHNOLOGYCHECKER_TIMEOUT, verify=certifi.where())
        response.raise_for_status()
        payload = response.json()
    except Exception:
        return {"available": False, "source": "technologychecker.io", "cms": [], "libraries": [], "plugins": [], "frameworks": []}

    enriched = {"available": True, "source": "technologychecker.io", "cms": [], "libraries": [], "plugins": [], "frameworks": []}
    seen = {key: set() for key in ("cms", "libraries", "plugins", "frameworks")}

    for item in _walk_items(payload):
        raw_name = item.get("name") or item.get("technology") or item.get("title")
        name = _normalize_name(raw_name)
        if not name:
            continue
        category = _item_category(item)
        if category == "other":
            continue

        target = {
            "cms": "cms",
            "plugin": "plugins",
            "library": "libraries",
            "framework": "frameworks",
        }[category]
        key = _canonical_key(name)
        if key in seen[target]:
            continue
        seen[target].add(key)

        enriched[target].append(
            {
                "name": name,
                "detected_version": _normalize_version(item.get("version") or item.get("detectedVersion")),
                "recommended_version": "Current maintained release",
                "confidence": _coerce_confidence(item),
                "evidence": "External enrichment from technologychecker.io",
                "source": "external",
            }
        )

    return enriched
