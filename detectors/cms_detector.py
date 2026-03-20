CMS_RULES = [
    {
        "name": "Drupal",
        "family": "Traditional CMS",
        "signals": [
            {"label": "generator", "patterns": ["drupal"], "weight": 9, "source": "generator"},
            {"label": "asset", "patterns": ["Drupal.settings", "drupal-settings-json", "/sites/default/files"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "WordPress",
        "family": "Traditional CMS",
        "signals": [
            {"label": "generator", "patterns": ["wordpress"], "weight": 9, "source": "generator"},
            {"label": "asset", "patterns": ["wp-content", "wp-includes", "wp-json"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "Joomla",
        "family": "Traditional CMS",
        "signals": [
            {"label": "generator", "patterns": ["joomla"], "weight": 9, "source": "generator"},
            {"label": "asset", "patterns": ["Joomla!", "/media/system/js", "/templates/system/"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "Magento",
        "family": "Commerce Platform",
        "signals": [
            {"label": "generator", "patterns": ["magento"], "weight": 9, "source": "generator"},
            {"label": "asset", "patterns": ["/static/frontend", "mage/cookies"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "Shopify",
        "family": "Managed Commerce Platform",
        "signals": [
            {"label": "asset", "patterns": ["cdn.shopify.com", "shopify-checkout-api-token", "shopify.theme"], "weight": 4, "source": "html"},
            {"label": "header", "patterns": ["x-shopify-stage", "x-shopify-request-id", "server:shopify"], "weight": 5, "source": "headers"},
        ],
    },
    {
        "name": "Wix",
        "family": "Proprietary Website Builder",
        "signals": [
            {"label": "asset", "patterns": ["wixstatic.com", "_wixcss", "wix-code-sdk"], "weight": 4, "source": "html"},
            {"label": "header", "patterns": ["x-wix-request-id"], "weight": 5, "source": "headers"},
        ],
    },
    {
        "name": "Squarespace",
        "family": "Proprietary Website Builder",
        "signals": [
            {"label": "asset", "patterns": ["static.squarespace.com", "squarespace-cdn", "static1.squarespace.com"], "weight": 4, "source": "html"},
            {"label": "generator", "patterns": ["squarespace"], "weight": 8, "source": "generator"},
        ],
    },
    {
        "name": "Webflow",
        "family": "Proprietary Website Builder",
        "signals": [
            {"label": "asset", "patterns": ["webflow.js", "webflow.io", "w-webflow-"], "weight": 4, "source": "html"},
            {"label": "generator", "patterns": ["webflow"], "weight": 8, "source": "generator"},
        ],
    },
    {
        "name": "Ghost",
        "family": "Traditional CMS",
        "signals": [
            {"label": "generator", "patterns": ["ghost"], "weight": 9, "source": "generator"},
            {"label": "asset", "patterns": ["ghost-sdk", "/ghost/api/", "ghost-content"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "TYPO3",
        "family": "Traditional CMS",
        "signals": [
            {"label": "generator", "patterns": ["typo3"], "weight": 9, "source": "generator"},
            {"label": "asset", "patterns": ["typo3conf", "typo3temp"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "Sitefinity",
        "family": "Proprietary Enterprise CMS",
        "signals": [
            {"label": "api", "patterns": ["x-sf-service-request", "/api/default/", "/restapi/markup"], "weight": 4, "source": "html"},
            {"label": "asset", "patterns": ["telerik.sitefinity", "progress.sitefinity.headless"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "SharePoint",
        "family": "Proprietary Enterprise CMS",
        "signals": [
            {"label": "page", "patterns": ["_layouts/15/start.aspx", "/_layouts/15/"], "weight": 4, "source": "html"},
            {"label": "service", "patterns": ["/_vti_bin/", "sharepoint"], "weight": 3, "source": "html"},
        ],
    },
    {
        "name": "Contentful",
        "family": "Headless CMS",
        "signals": [
            {"label": "api", "patterns": ["cdn.contentful.com", "images.ctfassets.net", ".contentful.com/"], "weight": 4, "source": "html"},
            {"label": "header", "patterns": ["x-contentful"], "weight": 6, "source": "headers"},
        ],
    },
    {
        "name": "CivicPlus HCMS",
        "family": "Headless CMS",
        "signals": [
            {"label": "api", "patterns": ["content.civicplus.com", "api/content/", "api/assets/"], "weight": 4, "source": "html"},
            {"label": "docs", "patterns": ["/docs", "graphql"], "weight": 1, "source": "html"},
        ],
    },
    {
        "name": "CivicPlus Web Central",
        "family": "Proprietary Government CMS",
        "signals": [
            {"label": "module", "patterns": ["/alertcenter/", "/documentcenter/", "/formcenter/", "/facilities/"], "weight": 4, "source": "html"},
            {"label": "page", "patterns": ["/calendar.aspx", "/civicalerts.aspx", "/bidpostings/"], "weight": 3, "source": "html"},
        ],
    },
    {
        "name": "CivicLive",
        "family": "Proprietary Government CMS",
        "signals": [
            {"label": "footer", "patterns": ["powered by civiclive", "civiclive", "civiclive.com"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "ProdCity",
        "family": "Proprietary Government CMS",
        "signals": [
            {"label": "footer", "patterns": ["powered by prodcity", "prodcity", "prod.city"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "TerminalFour",
        "family": "Proprietary Enterprise CMS",
        "signals": [
            {"label": "footer", "patterns": ["powered by terminalfour", "terminalfour", "terminal four"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "Sanity",
        "family": "Headless CMS",
        "signals": [
            {"label": "api", "patterns": ["cdn.sanity.io", "sanity.io/images", "sanity/studio"], "weight": 4, "source": "html"},
            {"label": "header", "patterns": ["x-sanity-project-id"], "weight": 6, "source": "headers"},
        ],
    },
    {
        "name": "Strapi",
        "family": "Headless CMS",
        "signals": [
            {"label": "api", "patterns": ["/uploads/", "strapi"], "weight": 2, "source": "html"},
            {"label": "header", "patterns": ["x-powered-by:strapi"], "weight": 7, "source": "headers"},
        ],
    },
    {
        "name": "Storyblok",
        "family": "Headless CMS",
        "signals": [
            {"label": "api", "patterns": ["a.storyblok.com", "app.storyblok.com", "img2.storyblok.com"], "weight": 4, "source": "html"},
            {"label": "header", "patterns": ["x-storyblok"], "weight": 6, "source": "headers"},
        ],
    },
    {
        "name": "Prismic",
        "family": "Headless CMS",
        "signals": [
            {"label": "api", "patterns": ["images.prismic.io", "cdn.prismic.io", ".prismic.io/"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "Contentstack",
        "family": "Headless CMS",
        "signals": [
            {"label": "api", "patterns": ["images.contentstack.io", "cdn.contentstack.io"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "Hygraph",
        "family": "Headless CMS",
        "signals": [
            {"label": "api", "patterns": ["media.graphassets.com", "graphassets.com"], "weight": 4, "source": "html"},
        ],
    },
    {
        "name": "Sitecore",
        "family": "Proprietary Enterprise CMS",
        "signals": [
            {"label": "asset", "patterns": ["/sitecore/", "sitecore/shell"], "weight": 4, "source": "html"},
            {"label": "header", "patterns": ["x-aspnetmvc-version", "sc_mode"], "weight": 2, "source": "headers"},
        ],
    },
    {
        "name": "Granicus govAccess",
        "family": "Proprietary Government CMS",
        "signals": [
            {"label": "brand", "patterns": ["govaccess", "visioninternet"], "weight": 4, "source": "html"},
            {"label": "vendor", "patterns": ["granicus"], "weight": 1, "source": "html"},
        ],
    },
    {
        "name": "OpenCities",
        "family": "Proprietary Government CMS",
        "signals": [
            {"label": "brand", "patterns": ["opencities", "websites & cms oe"], "weight": 4, "source": "html"},
            {"label": "vendor", "patterns": ["granicus"], "weight": 1, "source": "html"},
        ],
    },
    {
        "name": "Adobe Experience Manager",
        "family": "Proprietary Enterprise CMS",
        "signals": [
            {"label": "asset", "patterns": ["/etc.clientlibs/", "/content/dam/", "/libs/granite/"], "weight": 4, "source": "html"},
            {"label": "header", "patterns": ["x-adobe", "dispatcher"], "weight": 2, "source": "headers"},
        ],
    },
]

NO_CMS_MESSAGE = "No strong CMS fingerprint detected"


def _build_search_spaces(html: str, headers=None, meta_generator: str = "", assets=None) -> dict:
    header_blob = " ".join(f"{key}:{value}" for key, value in (headers or {}).items())
    asset_blob = " ".join(assets or [])
    combined = " ".join([html or "", meta_generator or "", asset_blob, header_blob]).lower()
    return {
        "html": combined,
        "headers": header_blob.lower(),
        "generator": (meta_generator or "").lower(),
    }


def _evidence_entry(source: str, label: str, pattern: str) -> dict:
    return {
        "source": source,
        "signal": label,
        "pattern": pattern,
    }


def _score_family_priority(family: str) -> int:
    priority = {
        "Traditional CMS": 4,
        "Commerce Platform": 4,
        "Managed Commerce Platform": 4,
        "Proprietary Enterprise CMS": 4,
        "Proprietary Government CMS": 4,
        "Proprietary Website Builder": 3,
        "Headless CMS": 2,
    }
    return priority.get(family, 1)


def _confidence_label(score: int) -> str:
    if score >= 9:
        return "Very High"
    if score >= 6:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def _match_rule(rule: dict, search_spaces: dict) -> dict | None:
    score = 0
    evidence = []

    for signal in rule["signals"]:
        source = signal["source"]
        haystack = search_spaces.get(source, "")
        matched_patterns = []
        for pattern in signal["patterns"]:
            if pattern.lower() in haystack:
                matched_patterns.append(pattern)

        if matched_patterns:
            score += signal["weight"]
            evidence.extend(
                _evidence_entry(source, signal["label"], pattern)
                for pattern in matched_patterns[:3]
            )

    if score < 4:
        return None

    return {
        "name": rule["name"],
        "family": rule["family"],
        "score": score,
        "confidence": _confidence_label(score),
        "evidence": evidence[:5],
    }


def _choose_primary(matches: list[dict]) -> dict:
    non_headless = [item for item in matches if item["family"] != "Headless CMS"]
    primary_pool = non_headless or matches
    return sorted(
        primary_pool,
        key=lambda item: (
            item["score"],
            _score_family_priority(item["family"]),
            len(item["evidence"]),
        ),
        reverse=True,
    )[0]


def _summarize_matches(matches: list[dict], primary_name: str | None) -> str:
    if not matches:
        return NO_CMS_MESSAGE

    parts = []
    for item in matches:
        role = "primary" if item["name"] == primary_name else "secondary"
        parts.append(f'{item["name"]} ({role}, {item["family"].lower()}, {item["confidence"].lower()} confidence)')
    return "; ".join(parts)


def detect_cms_profile(html: str, headers=None, meta_generator: str = "", assets=None) -> dict:
    """Infer CMS platforms from passive public signals with primary/secondary ranking."""
    search_spaces = _build_search_spaces(html, headers, meta_generator, assets)
    matches = []

    for rule in CMS_RULES:
        match = _match_rule(rule, search_spaces)
        if match:
            matches.append(match)

    matches.sort(
        key=lambda item: (
            item["score"],
            _score_family_priority(item["family"]),
            len(item["evidence"]),
        ),
        reverse=True,
    )

    if not matches:
        return {
            "primary": None,
            "secondary": [],
            "matches": [],
            "summary": NO_CMS_MESSAGE,
        }

    primary = _choose_primary(matches)
    ranked = [primary] + [item for item in matches if item["name"] != primary["name"]]
    ranked = [
        {
            **item,
            "role": "Primary" if index == 0 else "Secondary",
        }
        for index, item in enumerate(ranked)
    ]

    return {
        "primary": ranked[0],
        "secondary": ranked[1:],
        "matches": ranked,
        "summary": _summarize_matches(ranked, ranked[0]["name"]),
    }


def detect_cms(html: str, headers=None, meta_generator: str = "", assets=None) -> str:
    """Backward-compatible primary CMS label for existing callers."""
    profile = detect_cms_profile(html, headers, meta_generator, assets)
    if profile["primary"]:
        return profile["primary"]["name"]
    return NO_CMS_MESSAGE
