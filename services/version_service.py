import json
import re
import time

import certifi
import requests


OFFICIAL_RELEASE_TRACKS = {
    "WordPress": "6.9.4",
    "Drupal": "11.3.3 current; 10.6.3 supported for Drupal 10 sites",
    "Joomla": "6.0.x current; 5.4.x supported for Joomla 5 sites",
    "Magento": "2.4.8",
    "Shopify": "Managed SaaS",
    "Ghost": "6.x",
    "TYPO3": "13.4 LTS",
    "Craft CMS": "5.x current; 4.x still seen on maintained installs",
    "ButterCMS": "Managed SaaS",
    "Sitefinity": "Vendor-managed / not reliably exposed publicly",
    "SharePoint": "Microsoft-managed / tenant-specific",
    "CivicPlus Web Central": "Vendor-managed / not reliably exposed publicly",
    "CivicPlus HCMS": "Vendor-managed / not reliably exposed publicly",
    "CivicLive": "Vendor-managed / not reliably exposed publicly",
    "ProdCity": "Vendor-managed / not reliably exposed publicly",
    "TerminalFour": "Vendor-managed / not reliably exposed publicly",
    "Granicus govAccess": "Vendor-managed / not reliably exposed publicly",
    "OpenCities": "Vendor-managed / not reliably exposed publicly",
    "CakePHP": "5.x current; 4.x commonly maintained",
    "Zend Framework": "Deprecated; migrate to Laminas",
    "Laravel": "12.x",
    "Next.js": "16.0.10 current; 15.5.9 latest 15.x patch",
    "Nuxt": "4.2.x current; 3.18.x maintained",
    "Vue.js": "3.5.x",
    "Angular": "21.x",
    "AngularJS": "Deprecated",
    "React": "19.2",
    "Astro": "5.5.x",
    "Gatsby": "5.16.x",
    "Docusaurus": "3.9.x",
    "Svelte": "5.x",
    "SvelteKit": "2.x",
    "Sapper": "Deprecated; migrate to SvelteKit",
    "Wix": "Managed SaaS",
    "Squarespace": "Managed SaaS",
    "Webflow": "Managed SaaS",
}

OFFICIAL_RELEASE_SOURCES = {
    "WordPress": "https://api.wordpress.org/core/version-check/1.7/",
    "Drupal": "https://www.drupal.org/project/drupal/releases",
    "Joomla": "https://developer.joomla.org/news.html",
    "Magento": "https://experienceleague.adobe.com/docs/commerce-operations/release/versions.html",
    "Ghost": "https://ghost.org/changelog/",
    "TYPO3": "https://typo3.org/article/typo3-v13-lts-ride-the-wave",
    "Craft CMS": "https://craftcms.com/docs",
    "ButterCMS": "https://buttercms.com/docs/",
    "Sitefinity": "https://www.progress.com/documentation/sitefinity-cms/web-service-routes",
    "SharePoint": "https://learn.microsoft.com/en-us/sharepoint/dev/general-development/minimal-download-strategy-overview",
    "CivicPlus Web Central": "https://www.civicengagecentral.civicplus.help/hc/en-us/articles/115004748093-APIs-and-Web-Central",
    "CivicPlus HCMS": "https://www.civicplus.help/docs/application-programming-interface-api",
    "CivicLive": "https://www.civiclive.com/",
    "ProdCity": "https://prod.city/",
    "TerminalFour": "https://www.terminalfour.com/",
    "Granicus govAccess": "https://granicus.com/granicus-resources/wa-journey-to-digital-gov/",
    "OpenCities": "https://granicus.com/granicus-resources/wa-journey-to-digital-gov/",
    "CakePHP": "https://book.cakephp.org/",
    "Zend Framework": "https://docs.laminas.dev/laminas-mvc/migration/",
    "Laravel": "https://laravel.com/docs/releases",
    "Next.js": "https://nextjs.org/blog/security-update-2025-12-11",
    "Nuxt": "https://nuxt.com/blog",
    "Vue.js": "https://vuejs.org/about/releases",
    "Angular": "https://angular.dev/update",
    "React": "https://react.dev/versions",
    "Astro": "https://astro.build/blog/astro-550/",
    "Gatsby": "https://www.gatsbyjs.com/docs/reference/release-notes/",
    "Docusaurus": "https://docusaurus.io/blog",
    "Svelte": "https://svelte.dev/packages",
    "SvelteKit": "https://svelte.dev/docs/kit",
    "Sapper": "https://sapper.svelte.dev/docs/",
}

SUPPORTED_RELEASE_LINES = {
    "WordPress": {"6": "6.9.4"},
    "Drupal": {"11": "11.3.3", "10": "10.6.3"},
    "Joomla": {"6": "6.0.0", "5": "5.4.0"},
    "Magento": {"2": "2.4.8"},
    "Ghost": {"6": "6.0.0"},
    "TYPO3": {"13": "13.4.0"},
    "Craft CMS": {"5": "5.0.0", "4": "4.0.0"},
    "CakePHP": {"5": "5.0.0", "4": "4.0.0"},
    "Laravel": {"12": "12.0.0"},
    "Next.js": {"16": "16.0.10", "15": "15.5.9"},
    "Nuxt": {"4": "4.2.0", "3": "3.18.0"},
    "Vue.js": {"3": "3.5.0"},
    "Angular": {"21": "21.0.0"},
    "React": {"19": "19.2.0"},
    "Astro": {"5": "5.5.0"},
    "Gatsby": {"5": "5.16.0"},
    "Docusaurus": {"3": "3.9.0"},
    "Svelte": {"5": "5.0.0"},
    "SvelteKit": {"2": "2.0.0"},
}

DEPRECATED_TECHNOLOGIES = {
    "AngularJS": "AngularJS is end-of-life and should be migrated to a supported Angular or alternative frontend stack.",
    "Sapper": "Sapper is deprecated and no longer receives fixes. Migrate to SvelteKit.",
    "Zend Framework": "Zend Framework is deprecated. Migrate to Laminas or another supported PHP framework.",
}

MANAGED_PLATFORMS = {
    "Shopify",
    "Wix",
    "Squarespace",
    "Webflow",
    "ButterCMS",
    "Sitefinity",
    "SharePoint",
    "CivicPlus Web Central",
    "CivicPlus HCMS",
    "CivicLive",
    "ProdCity",
    "TerminalFour",
    "Granicus govAccess",
    "OpenCities",
}

PLATFORM_PRIORITY = [
    "Drupal",
    "WordPress",
    "Joomla",
    "Magento",
    "TYPO3",
    "Craft CMS",
    "Ghost",
    "ButterCMS",
    "Sitefinity",
    "SharePoint",
    "CivicPlus Web Central",
    "CivicPlus HCMS",
    "CivicLive",
    "ProdCity",
    "TerminalFour",
    "Granicus govAccess",
    "OpenCities",
    "CakePHP",
    "Zend Framework",
    "Shopify",
    "Laravel",
    "Next.js",
    "Nuxt",
    "Astro",
    "Docusaurus",
    "Gatsby",
    "Angular",
    "AngularJS",
    "Vue.js",
    "React",
    "SvelteKit",
    "Svelte",
    "Sapper",
    "Wix",
    "Squarespace",
    "Webflow",
]

VERSION_PATTERNS = {
    "WordPress": [
        re.compile(r"WordPress\s+((?:\d+\.){1,2}\d+)", re.IGNORECASE),
        re.compile(r"/wp-includes/[^\"'\s?#]+(?:\?[^\"']*)?[?&](?:ver|v)=((?:\d+\.){1,2}\d+)", re.IGNORECASE),
        re.compile(r"/wp-admin/(?:load-scripts|load-styles)\.php(?:\?[^\"']*)?[?&](?:ver|v)=((?:\d+\.){1,2}\d+)", re.IGNORECASE),
        re.compile(r"wp-emoji-release(?:\.min)?\.js\?ver=((?:\d+\.){1,2}\d+)", re.IGNORECASE),
    ],
    "Drupal": [
        re.compile(r"Drupal(?:\s+Core)?\s+(\d+(?:\.\d+){0,2})", re.IGNORECASE),
        re.compile(r"/core/misc/drupal(?:\.min)?\.js(?:\?[^\"']*)?[?&](?:v|ver)=(\d+(?:\.\d+){0,2})", re.IGNORECASE),
        re.compile(r"drupalSettings[^<]{0,400}?\"version\"\s*:\s*\"(\d+(?:\.\d+){0,2})", re.IGNORECASE),
    ],
    "Joomla": [
        re.compile(r"Joomla!?(?:\s+CMS)?\s+(\d+(?:\.\d+){0,2})", re.IGNORECASE),
    ],
    "Magento": [
        re.compile(r"Magento(?:\s+Open Source|\s+Commerce)?\s+(\d+(?:\.\d+){0,2}(?:-p\d+)?)", re.IGNORECASE),
    ],
    "Ghost": [
        re.compile(r"Ghost\s+(\d+(?:\.\d+){0,2})", re.IGNORECASE),
    ],
    "TYPO3": [
        re.compile(r"TYPO3(?:\s+CMS)?\s+(\d+(?:\.\d+){0,2})", re.IGNORECASE),
    ],
    "Laravel": [
        re.compile(r"Laravel(?:\s+Framework)?\s+v?(\d+(?:\.\d+){0,2})", re.IGNORECASE),
    ],
    "Angular": [
        re.compile(r"ng-version=[\"'](\d+(?:\.\d+){0,2})", re.IGNORECASE),
    ],
    "Vue.js": [
        re.compile(r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?[-.]?(\d+\.\d+(?:\.\d+)?)\.js", re.IGNORECASE),
        re.compile(r"Vue\.version\s*=\s*[\"'](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    ],
    "React": [
        re.compile(r"react(?:\.production)?(?:\.min)?[-.]?(\d+\.\d+(?:\.\d+)?)\.js", re.IGNORECASE),
        re.compile(r"react@(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    ],
    "Next.js": [
        re.compile(r"next(?:@|[-.])(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        re.compile(r"/_next/static/[^\"'\s?#]*next[-.]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    ],
    "Nuxt": [
        re.compile(r"nuxt(?:@|[-.])(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        re.compile(r"/_nuxt/[^\"'\s?#]*nuxt[-.]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    ],
    "Astro": [
        re.compile(r"astro(?:@|[-.])(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        re.compile(r"/_astro/[^\"'\s?#]*astro[-.]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    ],
    "Gatsby": [
        re.compile(r"gatsby(?:@|[-.])(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    ],
    "Docusaurus": [
        re.compile(r"docusaurus(?:@|[-.])(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    ],
    "Svelte": [
        re.compile(r"svelte(?:@|[-.])(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    ],
    "SvelteKit": [
        re.compile(r"@sveltejs/kit(?:@|/)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        re.compile(r"sveltekit(?:@|[-.])(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    ],
}

WORDPRESS_RELEASE_TTL_SECONDS = 6 * 60 * 60
_wordpress_release_cache: dict[str, object] = {"expires_at": 0.0, "data": None}


def _fetch_wordpress_release_data_live() -> dict | None:
    """Fetch WordPress release data from the official update API."""
    response = requests.get(
        OFFICIAL_RELEASE_SOURCES["WordPress"],
        timeout=8,
        verify=certifi.where(),
        headers={"Accept": "application/json"},
    )
    response.raise_for_status()
    payload = response.json()
    offers = payload.get("offers", [])
    if not offers:
        return None

    release_lines = {}
    latest_current = None
    for offer in offers:
        version = offer.get("current") or offer.get("version")
        if not version:
            continue
        major = version.split(".", 1)[0]
        current_for_line = release_lines.get(major)
        if current_for_line is None or _compare_versions(version, current_for_line) > 0:
            release_lines[major] = version
        if latest_current is None or _compare_versions(version, latest_current) > 0:
            latest_current = version

    if not latest_current:
        return None

    return {
        "current": latest_current,
        "release_lines": release_lines,
    }


def _get_wordpress_release_data() -> dict:
    """Return cached WordPress release data with a live refresh when possible."""
    now = time.time()
    cached = _wordpress_release_cache.get("data")
    expires_at = _wordpress_release_cache.get("expires_at", 0.0)
    if cached and now < expires_at:
        return cached

    try:
        fresh = _fetch_wordpress_release_data_live()
        if fresh:
            _wordpress_release_cache["data"] = fresh
            _wordpress_release_cache["expires_at"] = now + WORDPRESS_RELEASE_TTL_SECONDS
            return fresh
    except (requests.RequestException, ValueError, json.JSONDecodeError):
        pass

    fallback = {
        "current": OFFICIAL_RELEASE_TRACKS["WordPress"],
        "release_lines": SUPPORTED_RELEASE_LINES["WordPress"],
    }
    _wordpress_release_cache["data"] = fallback
    _wordpress_release_cache["expires_at"] = now + 300
    return fallback


def _best_version_match(matches: list[str]) -> str:
    """Prefer the most specific public version string when multiple matches exist."""
    return sorted(
        {match for match in matches if match},
        key=lambda value: (value.count("."), len(value)),
        reverse=True,
    )[0]


def _version_key(version: str) -> tuple[int, ...]:
    """Convert a semantic-ish version string into a numeric tuple for comparisons."""
    return tuple(int(part) for part in re.findall(r"\d+", version))


def _compare_versions(left: str, right: str) -> int:
    """Compare two version-like strings using their numeric components."""
    left_key = _version_key(left)
    right_key = _version_key(right)
    width = max(len(left_key), len(right_key))
    left_key += (0,) * (width - len(left_key))
    right_key += (0,) * (width - len(right_key))
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def _detected_major(version: str) -> str | None:
    """Return the major version as a string when one is available."""
    key = _version_key(version)
    if not key:
        return None
    return str(key[0])


def detect_cms_version(
    html: str,
    headers,
    assets,
    meta_generator: str,
    platform: str,
) -> str:
    """Detect a publicly exposed platform version from HTML, headers, assets, or metadata."""
    if not platform or platform == "No strong CMS fingerprint detected":
        return "Not publicly exposed"

    search_space = "\n".join(
        [
            html or "",
            meta_generator or "",
            "\n".join(assets or []),
            "\n".join(f"{key}:{value}" for key, value in (headers or {}).items()),
        ]
    )

    matches = []
    for pattern in VERSION_PATTERNS.get(platform, []):
        match = pattern.search(search_space)
        if match:
            matches.append(match.group(1))

    if matches:
        return _best_version_match(matches)

    return "Not publicly exposed"


def infer_primary_platform(cms: str, technology_stack) -> str:
    """Choose the most meaningful platform or framework to summarize in the report."""
    if cms and cms != "No strong CMS fingerprint detected":
        return cms

    detected_names = {item["name"] for item in (technology_stack or [])}
    for platform in PLATFORM_PRIORITY:
        if platform in detected_names:
            return platform

    return cms or "No strong CMS fingerprint detected"


def recommended_cms_version(platform: str) -> str:
    """Return the current recommended release track from official project sources."""
    if platform == "WordPress":
        return _get_wordpress_release_data()["current"]
    return OFFICIAL_RELEASE_TRACKS.get(platform, "No CMS release track inferred")


def assess_technology(name: str, detected_version: str) -> dict:
    """Classify an observed technology as current, review, outdated, or deprecated."""
    if name in DEPRECATED_TECHNOLOGIES:
        return {
            "status": "Deprecated",
            "status_reason": DEPRECATED_TECHNOLOGIES[name],
            "risk_level": "high",
            "recommended_track": recommended_cms_version(name),
        }

    if name in MANAGED_PLATFORMS:
        return {
            "status": "Managed",
            "status_reason": "This platform is vendor-managed, so version lifecycle is controlled upstream rather than publicly exposed per site.",
            "risk_level": "low",
            "recommended_track": recommended_cms_version(name),
        }

    if not detected_version or detected_version == "Not publicly exposed":
        return {
            "status": "Observed",
            "status_reason": "Version was not publicly exposed, so lifecycle risk could not be confirmed passively.",
            "risk_level": "neutral",
            "recommended_track": recommended_cms_version(name),
        }

    supported_lines = (
        _get_wordpress_release_data()["release_lines"]
        if name == "WordPress"
        else SUPPORTED_RELEASE_LINES.get(name)
    )
    if not supported_lines:
        return {
            "status": "Observed",
            "status_reason": "A public version was found, but no structured lifecycle comparison is configured for this technology yet.",
            "risk_level": "neutral",
            "recommended_track": recommended_cms_version(name),
        }

    detected_major = _detected_major(detected_version)
    current_major = max(int(line) for line in supported_lines)
    current_baseline = supported_lines[str(current_major)]

    if detected_major in supported_lines:
        baseline = supported_lines[detected_major]
        if _compare_versions(detected_version, baseline) < 0:
            return {
                "status": "Outdated",
                "status_reason": (
                    f"Observed version {detected_version} is behind the supported {detected_major}.x baseline "
                    f"({baseline})."
                ),
                "risk_level": "high",
                "recommended_track": recommended_cms_version(name),
            }
        if int(detected_major) < current_major:
            return {
                "status": "Review",
                "status_reason": (
                    f"Observed version {detected_version} appears to be on an older release line. "
                    f"The current line is {current_baseline}."
                ),
                "risk_level": "medium",
                "recommended_track": recommended_cms_version(name),
            }
        return {
            "status": "Current",
            "status_reason": f"Observed version {detected_version} aligns with the current supported release line.",
            "risk_level": "low",
            "recommended_track": recommended_cms_version(name),
        }

    if detected_major and int(detected_major) < current_major:
        return {
            "status": "Outdated",
            "status_reason": (
                f"Observed version {detected_version} appears to be outside the current supported release lines. "
                f"The current line is {current_baseline}."
            ),
            "risk_level": "high",
            "recommended_track": recommended_cms_version(name),
        }

    return {
        "status": "Observed",
        "status_reason": "A public version was found, but it could not be mapped to a supported release line confidently.",
        "risk_level": "neutral",
        "recommended_track": recommended_cms_version(name),
    }


def annotate_technology_stack(
    technology_stack,
    platform_name: str,
    platform_version: str,
    libraries,
):
    """Attach lifecycle and risk metadata to technology detections for reporting."""
    library_versions = {
        item["name"]: item.get("detected_version", "Not publicly exposed")
        for item in (libraries or [])
    }

    annotated = []
    for item in technology_stack or []:
        detected_version = "Not publicly exposed"
        if item["name"] == platform_name:
            detected_version = platform_version
        elif item["name"] in library_versions:
            detected_version = library_versions[item["name"]]

        assessment = assess_technology(item["name"], detected_version)
        annotated.append(
            {
                **item,
                "detected_version": detected_version,
                "status": assessment["status"],
                "status_reason": assessment["status_reason"],
                "risk_level": assessment["risk_level"],
                "recommended_track": assessment["recommended_track"],
            }
        )

    return annotated
