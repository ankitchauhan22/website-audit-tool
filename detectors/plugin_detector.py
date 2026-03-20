import re


PLUGIN_PATTERNS = [
    re.compile(r"wp-content/plugins/([^/?\"'#]+)/", re.IGNORECASE),
    re.compile(r"wp-content/mu-plugins/([^/?\"'#]+)/", re.IGNORECASE),
]

PLUGIN_VERSION_PATTERN = re.compile(
    r"wp-content/(?:mu-plugins|plugins)/([^/?\"'#]+)/[^\"'#?]*[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)",
    re.IGNORECASE,
)


def detect_wp_plugins(html: str, headers=None, assets=None):
    """Infer WordPress plugins from public asset URLs, markup, and headers."""
    combined = "\n".join(
        [
            html or "",
            "\n".join(assets or []),
            "\n".join(f"{key}:{value}" for key, value in (headers or {}).items()),
        ]
    )
    plugins = {}

    for pattern in PLUGIN_PATTERNS:
        for match in pattern.finditer(combined):
            name = match.group(1).strip().lower()
            if not name:
                continue
            plugins.setdefault(
                name,
                {
                    "name": name,
                    "detected_version": "Not publicly exposed",
                    "recommended_version": "Current supported release",
                },
            )

    for match in PLUGIN_VERSION_PATTERN.finditer(combined):
        name = match.group(1).strip().lower()
        version = match.group(2).strip()
        if not name:
            continue
        plugins.setdefault(
            name,
            {
                "name": name,
                "detected_version": "Not publicly exposed",
                "recommended_version": "Current supported release",
            },
        )
        plugins[name]["detected_version"] = version

    return sorted(plugins.values(), key=lambda plugin: plugin["name"].lower())
