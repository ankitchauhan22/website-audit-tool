import json
import re
from functools import lru_cache
from pathlib import Path


SOURCE_WEIGHTS = {
    "url": 28,
    "script": 32,
    "html": 24,
    "headers": 36,
    "meta": 42,
    "cookies": 34,
}


LOCAL_TECH_PATTERN_PATH = Path(__file__).resolve().parent / "data" / "technology_patterns.json"

SUPPORTED_PATTERN_APPS = {
    "WordPress",
    "Drupal",
    "Joomla",
    "Magento",
    "Google Analytics",
    "Google Tag Manager",
    "Hotjar",
    "jQuery",
}

CUSTOM_FINGERPRINTS = {
    "WordPress": {
        "categories": ["CMS", "Blogs"],
        "meta": {"generator": [r"WordPress(?: ([\d.]+))?;version:\1"]},
        "html": [
            r"<link[^>]+wp-(?:content|includes)",
            r"wp-json",
            r"/wp-content/",
            r"/wp-includes/",
        ],
    },
    "Drupal": {
        "categories": ["CMS"],
        "headers": {
            "X-Generator": [r"Drupal(?:\s([\d.]+))?;version:\1"],
            "X-Drupal-Cache": [r".+;confidence:25"],
            "Expires": [r"19 Nov 1978;confidence:25"],
        },
        "meta": {"generator": [r"Drupal(?:\s([\d.]+))?;version:\1"]},
        "html": [r"<(?:link|style)[^>]+sites/(?:default|all)/(?:themes|modules)/"],
        "script": [r"drupal(?:\.min)?\.js"],
    },
    "jQuery": {
        "categories": ["JavaScript Library"],
        "script": [
            r"jquery(?:\-|\.)([\d.]*\d)[^/]*\.js;version:\1",
            r"/([\d.]+)/jquery(?:\.min)?\.js;version:\1",
            r"jquery.*\.js;confidence:20",
        ],
    },
    "jQuery UI": {
        "categories": ["JavaScript Library"],
        "script": [
            r"jquery-ui(?:[-.]([\d.]+))?(?:\.min)?\.(?:js|css);version:\1",
            r"/jquery/ui/.*;confidence:30",
        ],
        "html": [r"\bui-(?:widget|datepicker|dialog|autocomplete)\b;confidence:22"],
    },
    "Bootstrap": {
        "categories": ["JavaScript Library", "UI Framework"],
        "script": [
            r"bootstrap(?:\.bundle)?(?:[-.]([\d.]+))?(?:\.min)?\.(?:js|css);version:\1",
        ],
        "html": [
            r"class=[\"'][^\"']*\bcontainer(?:-fluid)?\b;confidence:14",
            r"class=[\"'][^\"']*\brow\b;confidence:10",
        ],
    },
    "Swiper": {
        "categories": ["JavaScript Library"],
        "script": [r"swiper(?:[-.]([\d.]+))?(?:-bundle)?(?:\.min)?\.(?:js|css);version:\1"],
        "html": [r"\bswiper-(?:wrapper|slide)\b;confidence:20"],
    },
    "LazySizes": {
        "categories": ["Performance", "JavaScript Library"],
        "script": [r"lazysizes(?:[-.]([\d.]+))?(?:\.min)?\.js;version:\1"],
        "html": [r"\blazyload\b;confidence:18", r"data-src=;confidence:12"],
    },
    "AOS": {
        "categories": ["JavaScript Library"],
        "script": [r"(?:^|/)aos(?:[-.]([\d.]+))?(?:\.min)?\.(?:js|css);version:\1"],
        "html": [r"data-aos=;confidence:26"],
    },
    "core-js": {
        "categories": ["JavaScript Library"],
        "script": [r"core-js(?:[-.]([\d.]+))?;version:\1"],
    },
    "Underscore.js": {
        "categories": ["JavaScript Library"],
        "script": [r"underscore(?:[-.]([\d.]+))?(?:\.min)?\.js;version:\1"],
    },
    "Clipboard.js": {
        "categories": ["JavaScript Library"],
        "script": [r"clipboard(?:[-.]([\d.]+))?(?:\.min)?\.js;version:\1"],
    },
    "OWL Carousel": {
        "categories": ["JavaScript Library"],
        "script": [r"owl(?:\.|-)carousel(?:[-.]([\d.]+))?(?:\.min)?\.(?:js|css);version:\1"],
        "html": [r"\bowl-carousel\b;confidence:18"],
    },
    "React": {
        "categories": ["Frontend"],
        "script": [r"react(?:\.production)?(?:\.min)?[-.]?([\d.]+)?\.js;version:\1"],
        "html": [r"data-reactroot;confidence:24"],
    },
    "Vue.js": {
        "categories": ["Frontend"],
        "script": [r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?[-.]?([\d.]+)?\.js;version:\1"],
        "html": [r"data-v-[a-f0-9]+;confidence:20"],
    },
    "Angular": {
        "categories": ["Frontend"],
        "html": [r"ng-version=[\"']([\d.]+)[\"'];version:\1", r"_ngcontent-;confidence:18"],
    },
    "Next.js": {
        "categories": ["Frontend"],
        "script": [r"_next/static/;confidence:30"],
        "html": [r"__next;confidence:28"],
    },
    "Nuxt": {
        "categories": ["Frontend"],
        "script": [r"_nuxt/;confidence:30"],
        "html": [r"__nuxt;confidence:28"],
    },
    "Astro": {
        "categories": ["Frontend"],
        "script": [r"_astro/;confidence:30"],
        "html": [r"astro-island;confidence:26"],
    },
    "Gatsby": {
        "categories": ["Frontend"],
        "html": [r"___gatsby;confidence:30", r"gatsby-script;confidence:18"],
    },
    "Google Analytics": {
        "categories": ["Analytics"],
        "html": [
            r"_gaq\.push\(\['_setAccount;confidence:30",
            r"i\['GoogleAnalyticsObject'\];confidence:34",
            r"ga\.async = true;confidence:24",
        ],
        "script": [r"google-analytics\.com/(?:ga|urchin|analytics)\.js;confidence:34"],
        "headers": {"Set-Cookie": [r"__utma;confidence:24"]},
    },
    "Google Tag Manager": {
        "categories": ["Tag Manager"],
        "script": [r"googletagmanager\.com/gtm\.js;confidence:36"],
        "html": [r"GTM-[A-Z0-9]+;confidence:26"],
    },
    "Hotjar": {
        "categories": ["Analytics"],
        "script": [r"static\.hotjar\.com;confidence:34"],
        "html": [r"hotjar;confidence:22"],
    },
    "Meta Pixel": {
        "categories": ["Marketing"],
        "script": [r"connect\.facebook\.net/.*/fbevents\.js;confidence:34"],
        "html": [r"\bfbq\(;confidence:26"],
    },
}

CATEGORY_NAME_MAP = {
    "cms": "CMS",
    "blogs": "Blogs",
    "ecommerce": "Commerce",
    "analytics": "Analytics",
    "tag-managers": "Tag Manager",
    "javascript-frameworks": "JavaScript Library",
    "web-servers": "Hosting",
}


def _normalize_patterns(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


@lru_cache(maxsize=1)
def _load_pattern_fingerprints():
    if not LOCAL_TECH_PATTERN_PATH.exists():
        return {}

    data = json.loads(LOCAL_TECH_PATTERN_PATH.read_text(encoding="utf-8"))
    apps = data.get("apps", {})
    categories = data.get("categories", {})
    fingerprints = {}

    for app_name in SUPPORTED_PATTERN_APPS:
        app = apps.get(app_name)
        if not app:
            continue

        mapped_categories = []
        for category_id in app.get("cats", []):
            raw_name = categories.get(str(category_id), "")
            mapped_categories.append(CATEGORY_NAME_MAP.get(raw_name, raw_name.title() if raw_name else "Technology"))

        fingerprint = {"categories": mapped_categories or ["Technology"]}
        for source_key in ("url", "html", "script"):
            if source_key in app:
                fingerprint[source_key] = _normalize_patterns(app[source_key])
        if "headers" in app:
            fingerprint["headers"] = {
                key: _normalize_patterns(value)
                for key, value in app["headers"].items()
            }
        if "meta" in app:
            fingerprint["meta"] = {
                key: _normalize_patterns(value)
                for key, value in app["meta"].items()
            }
        fingerprints[app_name] = fingerprint

    return fingerprints


def _all_fingerprints():
    fingerprints = dict(_load_pattern_fingerprints())
    fingerprints.update(CUSTOM_FINGERPRINTS)
    return fingerprints


def _parse_pattern_spec(spec: str):
    normalized = spec.replace(r"\;version:", ";version:").replace(r"\;confidence:", ";confidence:")
    sentinel = "__WAPPALYZER_ESCAPED_SEMI__"
    pattern = normalized.replace(r"\;", sentinel)
    version_group = None
    confidence = None

    if ";version:" in pattern:
        pattern, version_part = pattern.split(";version:", 1)
        version_group = version_part.strip()
    if ";confidence:" in pattern:
        pattern, confidence_part = pattern.split(";confidence:", 1)
        confidence = int(confidence_part.strip())
    elif version_group and ";confidence:" in version_group:
        version_group, confidence_part = version_group.split(";confidence:", 1)
        confidence = int(confidence_part.strip())

    pattern = pattern.replace(sentinel, r"\;")
    if version_group:
        version_group = version_group.replace(sentinel, r"\;")

    return pattern, version_group, confidence


def _extract_version_from_match(match: re.Match, version_spec: str | None) -> str:
    if not version_spec:
        return "Not publicly exposed"
    version = version_spec.strip()
    if version.startswith("\\"):
        try:
            group_index = int(version[1:])
        except ValueError:
            return "Not publicly exposed"
        try:
            value = match.group(group_index)
        except IndexError:
            return "Not publicly exposed"
        return value or "Not publicly exposed"
    return version or "Not publicly exposed"


def _match_source_patterns(source_name: str, patterns, haystack: str):
    matches = []
    for spec in _normalize_patterns(patterns):
        pattern, version_spec, confidence_override = _parse_pattern_spec(spec)
        match = re.search(pattern, haystack or "", re.IGNORECASE)
        if not match:
            continue
        matches.append(
            {
                "source": source_name,
                "pattern": pattern,
                "evidence": match.group(0)[:120],
                "version": _extract_version_from_match(match, version_spec),
                "confidence": confidence_override if confidence_override is not None else SOURCE_WEIGHTS.get(source_name, 20),
            }
        )
    return matches


def run_fingerprint_scan(url: str, html: str, headers: dict, meta_generator: str, assets: list[str], cookies: list[str]):
    flattened_headers = {str(key): str(value) for key, value in (headers or {}).items()}
    script_haystack = "\n".join(assets or [])
    cookie_haystack = "\n".join(cookies or [])

    findings = []
    for name, fingerprint in _all_fingerprints().items():
        matched = []
        matched.extend(_match_source_patterns("url", fingerprint.get("url"), url or ""))
        matched.extend(_match_source_patterns("html", fingerprint.get("html"), html or ""))
        matched.extend(_match_source_patterns("script", fingerprint.get("script"), script_haystack))
        matched.extend(_match_source_patterns("cookies", fingerprint.get("cookies"), cookie_haystack))

        for meta_name, meta_patterns in (fingerprint.get("meta") or {}).items():
            meta_value = meta_generator if meta_name.lower() == "generator" else ""
            matched.extend(_match_source_patterns("meta", meta_patterns, meta_value))

        for header_name, header_patterns in (fingerprint.get("headers") or {}).items():
            header_value = flattened_headers.get(header_name) or flattened_headers.get(header_name.lower()) or ""
            matched.extend(_match_source_patterns("headers", header_patterns, header_value))

        if not matched:
            continue

        score = min(100, sum(item["confidence"] for item in matched[:4]))
        if score >= 75:
            confidence = "High"
        elif score >= 40:
            confidence = "Medium"
        else:
            confidence = "Low"

        version = next(
            (item["version"] for item in matched if item["version"] not in {"", "Not publicly exposed", None}),
            "Not publicly exposed",
        )
        findings.append(
            {
                "name": name,
                "categories": list(fingerprint.get("categories", [])),
                "confidence": confidence,
                "confidence_score": score,
                "detected_version": version,
                "signals": matched[:4],
                "evidence": ", ".join(dict.fromkeys(item["evidence"] for item in matched[:3])),
            }
        )

    return findings
