import re


PLUGIN_ALIASES = {
    "yoast": "Yoast SEO",
    "yoast-seo": "Yoast SEO",
    "wordpress-seo": "Yoast SEO",
    "elementor": "Elementor",
    "woocommerce": "WooCommerce",
    "wordfence": "Wordfence",
    "wordfence-login-security": "Wordfence Login Security",
    "autoptimize": "Autoptimize",
    "wp-fastest-cache": "WP Fastest Cache",
    "wpfastestcache": "WP Fastest Cache",
    "contact-form-7": "Contact Form 7",
    "cookieyes": "CookieYes",
    "cookie-law-info": "CookieYes",
}


PLUGIN_PATTERNS = [
    re.compile(r"wp-content/plugins/([^/?\"'#]+)/", re.IGNORECASE),
    re.compile(r"wp-content/mu-plugins/([^/?\"'#]+)/", re.IGNORECASE),
    re.compile(r"['\" ](contact-form-7|elementor|woocommerce|wordfence|wordfence-login-security|yoast|yoast-seo|wordpress-seo|siteorigin-panels|revslider|js_composer|wpforms|gravityforms|cookie-law-info|cookieyes|wpml|autoptimize|wp-fastest-cache|wpfastestcache)[/'\" ]", re.IGNORECASE),
    re.compile(r"(?:data-|class=|id=)[^>\"']*(elementor|woocommerce|yoast|wordpress-seo|autoptimize|wpforms|gravityforms|cookieyes|contact-form-7|revslider|siteorigin-panels|wp-fastest-cache|wordfence-login-security)", re.IGNORECASE),
    re.compile(r"/(?:plugins|mu-plugins)/([^/?\"'#]+)/(?:assets|dist|build|js|css|public)/", re.IGNORECASE),
]

PLUGIN_VERSION_PATTERN = re.compile(
    r"wp-content/(?:mu-plugins|plugins)/([^/?\"'#]+)/[^\"'#?]*[?&](?:ver|version|v)=((?:\d+\.){1,3}\d+)",
    re.IGNORECASE,
)

PLUGIN_FILE_VERSION_PATTERN = re.compile(
    r"/(?:plugins|mu-plugins)/([^/?\"'#]+)/[^\"'#?]*[-.]((?:\d+\.){1,3}\d+)\.(?:js|css)",
    re.IGNORECASE,
)


def _normalize_plugin_name(name: str) -> str:
    slug = (name or "").strip().lower().replace("_", "-")
    return PLUGIN_ALIASES.get(slug, slug.replace("-", " ").title())


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
                    "name": _normalize_plugin_name(name),
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
                "name": _normalize_plugin_name(name),
                "detected_version": "Not publicly exposed",
                "recommended_version": "Current supported release",
            },
        )
        plugins[name]["detected_version"] = version

    for match in PLUGIN_FILE_VERSION_PATTERN.finditer(combined):
        name = match.group(1).strip().lower()
        version = match.group(2).strip()
        if not name:
            continue
        plugins.setdefault(
            name,
            {
                "name": _normalize_plugin_name(name),
                "detected_version": "Not publicly exposed",
                "recommended_version": "Current supported release",
            },
        )
        if plugins[name]["detected_version"] == "Not publicly exposed":
            plugins[name]["detected_version"] = version

    return sorted(plugins.values(), key=lambda plugin: plugin["name"].lower())
