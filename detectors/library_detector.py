import re
from urllib.parse import parse_qs, unquote, urlparse

from detectors.technology_matcher import run_fingerprint_scan


GENERIC_LIBRARY_BANNER_PATTERNS = [
    re.compile(r"/\*!\s*([A-Z][A-Za-z0-9_. +\-]{2,60}?)\s+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    re.compile(r"@license\s+([A-Z][A-Za-z0-9_. +\-]{2,60}?)\s+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    re.compile(r"([A-Z][A-Za-z0-9_. +\-]{2,60}?)\s+JavaScript\s+Library\s+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
]

GENERIC_LIBRARY_FILENAME = re.compile(
    r"/([A-Za-z][A-Za-z0-9_.+\-]{2,60}?)(?:\.min)?(?:[-._](\d+\.\d+(?:\.\d+)?))?\.(?:js|css)(?:[?#].*)?$",
    re.IGNORECASE,
)

GENERIC_LIBRARY_SEGMENT = re.compile(r"([A-Za-z][A-Za-z0-9_.+\-]{1,60})")

IGNORE_GENERIC_LIBRARY_NAMES = {
    "index",
    "main",
    "app",
    "bundle",
    "vendor",
    "runtime",
    "common",
    "scripts",
    "style",
    "styles",
    "theme",
    "frontend",
    "public",
    "global",
    "site",
    "core",
    "js",
    "css",
    "assets",
    "dist",
    "build",
    "chunk",
    "module",
    "modules",
    "plugins",
    "plugin",
    "libs",
    "lib",
    "vendor",
    "vendors",
    "min",
}

GENERIC_LIBRARY_BLOCKLIST = {
    "react",
    "vue",
    "vuejs",
    "angular",
    "angularjs",
    "next",
    "nextjs",
    "nuxt",
    "astro",
    "gatsby",
    "docusaurus",
    "svelte",
    "sveltekit",
    "remix",
    "wordpress",
    "drupal",
    "joomla",
    "magento",
    "shopify",
    "elementor",
    "yoast",
    "autoptimize",
    "cookieyes",
}

GENERIC_LIBRARY_ALIASES = {
    "aos": "AOS",
    "clipboard": "Clipboard.js",
    "clipboard js": "Clipboard.js",
    "core js": "core-js",
    "core-js": "core-js",
    "j query": "jQuery",
    "jquery": "jQuery",
    "jquery ui": "jQuery UI",
    "jquery ui core": "jQuery UI",
    "lazy sizes": "LazySizes",
    "lazysizes": "LazySizes",
    "owl carousel": "OWL Carousel",
    "swiper": "Swiper",
    "underscore": "Underscore.js",
    "underscore js": "Underscore.js",
    "vue": "Vue.js",
    "vue js": "Vue.js",
}


LIBRARY_RULES = [
    {
        "name": "Underscore.js",
        "recommended_version": "1.13.x",
        "asset_patterns": [re.compile(r"underscore(?:\.min)?\.js", re.IGNORECASE), re.compile(r"/underscore/", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"underscore[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [
            re.compile(r"Underscore\.js\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"VERSION\s*=\s*[\"'](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ],
    },
    {
        "name": "Clipboard.js",
        "recommended_version": "2.x",
        "asset_patterns": [re.compile(r"clipboard(?:\.min)?\.js", re.IGNORECASE), re.compile(r"/clipboard/", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"clipboard[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [
            re.compile(r"clipboard\.js v(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ],
    },
    {
        "name": "OWL Carousel",
        "recommended_version": "2.3.x",
        "asset_patterns": [re.compile(r"owl(?:\.|-)carousel", re.IGNORECASE), re.compile(r"/owlcarousel/", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"owl(?:\.|-)carousel[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [
            re.compile(r"OWL Carousel v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ],
    },
    {
        "name": "jQuery",
        "recommended_version": "3.7.1",
        "asset_patterns": [
            re.compile(r"(?:^|/)jquery(?:\.slim)?(?:\.min)?\.js(?:[?#].*)?$", re.IGNORECASE),
            re.compile(r"/jquery/(?:(?:dist|src)/)?jquery(?:\.slim)?(?:\.min)?\.js", re.IGNORECASE),
        ],
        "url_version_patterns": [
            re.compile(r"jquery[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [
            re.compile(r"jQuery v(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"jQuery JavaScript Library v(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ],
    },
    {
        "name": "Bootstrap",
        "recommended_version": "5.x",
        "asset_patterns": [re.compile(r"bootstrap", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"bootstrap[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [
            re.compile(r"Bootstrap v(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ],
    },
    {
        "name": "jQuery UI",
        "recommended_version": "1.14.x",
        "asset_patterns": [re.compile(r"jquery-ui", re.IGNORECASE), re.compile(r"/jquery/ui/", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"jquery-ui[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [
            re.compile(r"jQuery UI(?: Core)? (\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"version:\s*[\"'](\d+\.\d+(?:\.\d+)?)[\"']", re.IGNORECASE),
        ],
    },
    {
        "name": "Swiper",
        "recommended_version": "11.x",
        "asset_patterns": [re.compile(r"swiper", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"swiper[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [
            re.compile(r"Swiper\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ],
    },
    {
        "name": "LazySizes",
        "recommended_version": "5.x",
        "asset_patterns": [re.compile(r"lazysizes", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"lazysizes[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [
            re.compile(r"lazySizesConfig", re.IGNORECASE),
            re.compile(r"lazysizes(?:\.min)?\.js", re.IGNORECASE),
        ],
    },
    {
        "name": "core-js",
        "recommended_version": "3.x",
        "asset_patterns": [re.compile(r"core-js", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"core-js[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [
            re.compile(r"core-js(?:@| v)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ],
    },
    {
        "name": "AOS",
        "recommended_version": "2.3.x",
        "asset_patterns": [re.compile(r"(?:^|/)aos(?:\.min)?\.(?:js|css)", re.IGNORECASE), re.compile(r"/aos/", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"aos[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [
            re.compile(r"AOS(?:\s+version)?[: ](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"\.init\(", re.IGNORECASE),
        ],
    },
]


def _extract_version(patterns, text: str) -> str:
    for pattern in patterns:
        match = pattern.search(text or "")
        if match:
            if match.lastindex:
                return match.group(1)
            return "Not publicly exposed"
    return "Not publicly exposed"


def _normalize_generic_name(name: str) -> str:
    raw = unquote((name or "").strip())
    raw = re.sub(r"\.(?:min|slim|bundle|umd|esm|cjs)$", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"[-._]v?\d+(?:\.\d+){1,3}$", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"[-._][a-f0-9]{6,}$", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"\b(core|min|dist|prod|production|runtime|bundle|plugin)\b", " ", raw, flags=re.IGNORECASE)
    raw = re.sub(r"(?<!^)(?=[A-Z][a-z])", " ", raw)
    raw = re.sub(r"[-._]+", " ", raw)
    cleaned = re.sub(r"\s+", " ", raw).strip()
    if not cleaned:
        return ""
    words = []
    for token in cleaned.split():
        lower = token.lower()
        if lower in {"js", "css", "dist", "build", "bundle", "module", "plugin", "plugins"}:
            continue
        if token.isupper() and len(token) <= 5:
            words.append(token)
            continue
        if lower in {"ui", "ux", "cdn"}:
            words.append(lower.upper())
            continue
        if lower == "jquery":
            words.append("jQuery")
            continue
        if lower == "core-js":
            words.append("core-js")
            continue
        words.append(token.capitalize())
    normalized = " ".join(words).strip()
    alias_key = normalized.lower()
    return GENERIC_LIBRARY_ALIASES.get(alias_key, normalized)


def _is_generic_library_candidate(name: str) -> bool:
    normalized = (name or "").strip().lower().replace(".js", "").replace(".css", "")
    if not normalized or normalized in IGNORE_GENERIC_LIBRARY_NAMES:
        return False
    slug = normalized.replace(" ", "").replace("-", "")
    if normalized.startswith(("wp-", "jquery", "bootstrap")):
        return False
    if normalized in GENERIC_LIBRARY_BLOCKLIST or slug in GENERIC_LIBRARY_BLOCKLIST:
        return False
    if any(token in normalized for token in ("chunk", "runtime", "webpack", "polyfill", "manifest")):
        return False
    return any(character.isalpha() for character in normalized)


def _extract_asset_candidates(asset: str) -> list[str]:
    parsed = urlparse(asset or "")
    candidates = []

    for key in ("id", "handle", "module", "library"):
        for value in parse_qs(parsed.query).get(key, []):
            for token in re.split(r"[,\s]+", value):
                token = token.strip()
                if token:
                    candidates.append(token)

    path = unquote(parsed.path or "")
    parts = [part for part in path.split("/") if part]
    if parts:
        basename = parts[-1]
        stem = re.sub(r"\.(?:js|css)$", "", basename, flags=re.IGNORECASE)
        candidates.append(stem)
    for part in parts[-3:]:
        candidates.append(part)

    return candidates


def _candidate_score(raw_name: str, version: str | None = None) -> int:
    normalized = _normalize_generic_name(raw_name)
    if not _is_generic_library_candidate(normalized):
        return -100

    score = 0
    lowered = raw_name.lower()
    if version and version != "Not publicly exposed":
        score += 5
    if "-" in raw_name or "." in raw_name:
        score += 3
    if "min" not in lowered and "bundle" not in lowered:
        score += 3
    if 3 <= len(normalized) <= 28:
        score += 4
    if any(char.isupper() for char in raw_name[1:]):
        score += 2
    if lowered in IGNORE_GENERIC_LIBRARY_NAMES:
        score -= 10
    return score


def _best_generic_candidate(asset: str, body: str) -> tuple[str, str]:
    options = []

    filename_match = GENERIC_LIBRARY_FILENAME.search(asset or "")
    if filename_match:
        options.append((filename_match.group(1), filename_match.group(2) or "Not publicly exposed", 8))

    for candidate in _extract_asset_candidates(asset):
        if not GENERIC_LIBRARY_SEGMENT.search(candidate):
            continue
        version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", candidate)
        version = version_match.group(1) if version_match else "Not publicly exposed"
        options.append((candidate, version, 5))

    for pattern in GENERIC_LIBRARY_BANNER_PATTERNS:
        match = pattern.search(body or "")
        if match:
            options.append((match.group(1), match.group(2), 12))

    ranked = sorted(
        options,
        key=lambda item: (_candidate_score(item[0], item[1]) + item[2], len(_normalize_generic_name(item[0]))),
        reverse=True,
    )
    if not ranked:
        return "", "Not publicly exposed"

    best_name, best_version, _ = ranked[0]
    normalized_name = _normalize_generic_name(best_name)
    final_score = _candidate_score(best_name, best_version) + ranked[0][2]
    if final_score < 12 or not _is_generic_library_candidate(normalized_name):
        return "", "Not publicly exposed"
    return normalized_name, best_version or "Not publicly exposed"


def _canonical_library_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def _detect_generic_libraries(assets, asset_bodies) -> list[dict]:
    detected = {}

    for asset in assets:
        body = asset_bodies.get(asset, "")
        name, version = _best_generic_candidate(asset, body)
        if not name or not _is_generic_library_candidate(name):
            continue
        entry = detected.setdefault(
            name,
            {
                "name": name,
                "detected_version": "Not publicly exposed",
                "recommended_version": "Current maintained release",
                "assets": [],
                "confidence": "Low",
                "confidence_score": 28,
                "evidence": "Generic filename/banner match",
            },
        )
        if version and version != "Not publicly exposed":
            entry["detected_version"] = version
            entry["confidence"] = "Medium"
            entry["confidence_score"] = max(entry["confidence_score"], 42)
        if asset not in entry["assets"]:
            entry["assets"].append(asset)
            entry["evidence"] = ", ".join(dict.fromkeys([entry["evidence"], asset]))

    return list(detected.values())


def detect_libraries(assets, asset_bodies=None, html: str = ""):
    libraries = {}
    matched_assets = set()
    asset_bodies = asset_bodies or {}
    combined_html = html or ""

    for asset in assets:
        for rule in LIBRARY_RULES:
            if not any(pattern.search(asset) for pattern in rule["asset_patterns"]):
                continue

            version = _extract_version(rule["url_version_patterns"], asset)
            if version == "Not publicly exposed":
                version = _extract_version(rule["content_patterns"], asset_bodies.get(asset, ""))

            entry = libraries.setdefault(
                rule["name"],
                {
                    "name": rule["name"],
                    "detected_version": "Not publicly exposed",
                    "recommended_version": rule["recommended_version"],
                    "assets": [],
                },
            )
            if version != "Not publicly exposed":
                entry["detected_version"] = version
            if asset not in entry["assets"]:
                entry["assets"].append(asset)
                matched_assets.add(asset)

    for rule in LIBRARY_RULES:
        if rule["name"] in libraries:
            continue
        if any(pattern.search(combined_html) for pattern in rule["asset_patterns"]):
            version = _extract_version(rule["url_version_patterns"], combined_html)
            if version == "Not publicly exposed":
                version = _extract_version(rule["content_patterns"], combined_html)
            libraries[rule["name"]] = {
                "name": rule["name"],
                "detected_version": version,
                "recommended_version": rule["recommended_version"],
                "assets": [],
                "confidence": "Medium" if version != "Not publicly exposed" else "Low",
                "confidence_score": 55 if version != "Not publicly exposed" else 35,
                "evidence": "HTML/source match",
            }

    existing_keys = {_canonical_library_key(name) for name in libraries}
    for item in _detect_generic_libraries(assets, asset_bodies):
        if any(asset in matched_assets for asset in item.get("assets", [])):
            continue
        if _canonical_library_key(item["name"]) in existing_keys:
            continue
        libraries.setdefault(item["name"], item)

    combined_asset_html = "\n".join(filter(None, [combined_html, *assets, *asset_bodies.values()]))
    fingerprint_matches = run_fingerprint_scan("", combined_asset_html, {}, "", assets or [], [])
    library_categories = {"JavaScript Library", "UI Framework"}
    for item in fingerprint_matches:
        if not any(category in library_categories for category in item.get("categories", [])):
            continue
        if not any(signal.get("source") == "script" for signal in item.get("signals", [])):
            continue
        existing = libraries.get(item["name"])
        if existing:
            if existing.get("detected_version") in {None, "", "Not publicly exposed"} and item.get("detected_version") not in {None, "", "Not publicly exposed"}:
                existing["detected_version"] = item["detected_version"]
            existing["confidence"] = item.get("confidence", existing.get("confidence", "Medium"))
            existing["confidence_score"] = max(item.get("confidence_score", 0), existing.get("confidence_score", 0))
            existing["evidence"] = ", ".join(
                dict.fromkeys(
                    [part for part in [existing.get("evidence"), item.get("evidence")] if part]
                )
            )
            continue

        libraries[item["name"]] = {
            "name": item["name"],
            "detected_version": item.get("detected_version", "Not publicly exposed"),
            "recommended_version": "Current maintained release",
            "assets": [],
            "confidence": item.get("confidence", "Medium"),
            "confidence_score": item.get("confidence_score", 0),
            "evidence": item.get("evidence", "Pattern-based technology match"),
        }

    deduped = {}
    for item in libraries.values():
        key = _canonical_library_key(item.get("name", ""))
        existing = deduped.get(key)
        if not existing or item.get("confidence_score", 0) > existing.get("confidence_score", 0):
            deduped[key] = item

    return sorted(
        [
            item for item in deduped.values()
            if item.get("confidence_score", 0) >= 35
        ],
        key=lambda library: (-library.get("confidence_score", 0), library["name"].lower()),
    )
