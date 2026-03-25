import re


GENERIC_COMPONENT_PATTERNS = [
    re.compile(r"/modules/([^/?\"'#]+)/", re.IGNORECASE),
    re.compile(r"/extensions/([^/?\"'#]+)/", re.IGNORECASE),
    re.compile(r"/components/([^/?\"'#]+)/", re.IGNORECASE),
    re.compile(r"/plugins/([^/?\"'#]+)/", re.IGNORECASE),
    re.compile(r"/addons/([^/?\"'#]+)/", re.IGNORECASE),
    re.compile(r"/bundles/([^/?\"'#]+)/", re.IGNORECASE),
    re.compile(r"/(?:vendor|packages|libs)/([^/?\"'#]+)/", re.IGNORECASE),
    re.compile(r"(?:data-module|data-component|data-plugin)=[\"']([^\"']+)[\"']", re.IGNORECASE),
]

GENERIC_COMPONENT_VERSION_PATTERNS = [
    re.compile(
        r"/(?:modules|extensions|components|plugins|addons|bundles|vendor|packages|libs)/([^/?\"'#]+)/[^\"'#?]*[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"/(?:modules|extensions|components|plugins|addons|bundles|vendor|packages|libs)/([^/?\"'#]+)/[^\"'#?]*[-.]((?:\d+\.){1,3}\d+)\.(?:js|css)",
        re.IGNORECASE,
    ),
]


def detect_generic_components(html: str, headers=None, assets=None):
    """Infer generic module or extension names from public URLs and markup."""
    combined = "\n".join(
        [
            html or "",
            "\n".join(assets or []),
            "\n".join(f"{key}:{value}" for key, value in (headers or {}).items()),
        ]
    )
    components = {}

    for pattern in GENERIC_COMPONENT_PATTERNS:
        for match in pattern.finditer(combined):
            name = match.group(1).strip().lower()
            if not name:
                continue
            components.setdefault(
                name,
                {
                    "name": name,
                    "detected_version": "Not publicly exposed",
                    "recommended_version": "Current supported release",
                },
            )

    for pattern in GENERIC_COMPONENT_VERSION_PATTERNS:
        for match in pattern.finditer(combined):
            name = match.group(1).strip().lower()
            version = match.group(2).strip()
            if not name:
                continue
            components.setdefault(
                name,
                {
                    "name": name,
                    "detected_version": "Not publicly exposed",
                    "recommended_version": "Current supported release",
                },
            )
            components[name]["detected_version"] = version

    return sorted(components.values(), key=lambda component: component["name"].lower())
