import re


LIBRARY_RULES = [
    {
        "name": "jQuery",
        "recommended_version": "3.7.1",
        "asset_patterns": [re.compile(r"jquery", re.IGNORECASE)],
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
        "asset_patterns": [re.compile(r"jquery-ui", re.IGNORECASE)],
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
        "content_patterns": [],
    },
    {
        "name": "core-js",
        "recommended_version": "3.x",
        "asset_patterns": [re.compile(r"core-js", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"core-js[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [],
    },
    {
        "name": "AOS",
        "recommended_version": "2.3.x",
        "asset_patterns": [re.compile(r"(?:^|/)aos(?:\.min)?\.(?:js|css)", re.IGNORECASE), re.compile(r"/aos/", re.IGNORECASE)],
        "url_version_patterns": [
            re.compile(r"aos[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)", re.IGNORECASE),
        ],
        "content_patterns": [],
    },
    {
        "name": "React",
        "recommended_version": "19.2",
        "asset_patterns": [re.compile(r"react", re.IGNORECASE)],
        "url_version_patterns": [re.compile(r"react[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)],
        "content_patterns": [],
    },
    {
        "name": "Vue.js",
        "recommended_version": "3.5.x",
        "asset_patterns": [re.compile(r"vue", re.IGNORECASE)],
        "url_version_patterns": [re.compile(r"vue[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)],
        "content_patterns": [],
    },
    {
        "name": "Angular",
        "recommended_version": "21.x",
        "asset_patterns": [re.compile(r"angular", re.IGNORECASE)],
        "url_version_patterns": [re.compile(r"angular[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)],
        "content_patterns": [],
    },
    {
        "name": "Astro",
        "recommended_version": "5.5.x",
        "asset_patterns": [re.compile(r"astro", re.IGNORECASE)],
        "url_version_patterns": [re.compile(r"astro[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)],
        "content_patterns": [],
    },
    {
        "name": "Gatsby",
        "recommended_version": "5.16.x",
        "asset_patterns": [re.compile(r"gatsby", re.IGNORECASE)],
        "url_version_patterns": [re.compile(r"gatsby[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)],
        "content_patterns": [],
    },
]


def _extract_version(patterns, text: str) -> str:
    for pattern in patterns:
        match = pattern.search(text or "")
        if match:
            return match.group(1)
    return "Not publicly exposed"


def detect_libraries(assets, asset_bodies=None):
    libraries = {}
    asset_bodies = asset_bodies or {}

    for asset in assets:
        for rule in LIBRARY_RULES:
            if not any(pattern.search(asset) for pattern in rule["asset_patterns"]):
                continue

            version = _extract_version(rule["url_version_patterns"], asset)
            if version == "Not publicly exposed":
                version = _extract_version(rule["content_patterns"], asset_bodies.get(asset, ""))

            libraries[rule["name"]] = {
                "name": rule["name"],
                "detected_version": version,
                "recommended_version": rule["recommended_version"],
            }

    return sorted(libraries.values(), key=lambda library: library["name"].lower())
