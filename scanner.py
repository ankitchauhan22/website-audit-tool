from bs4 import BeautifulSoup

from audit_tool.fetcher import fetch_page
from detectors.cms_detector import NO_CMS_MESSAGE, detect_cms_profile
from detectors.drupal_detector import detect_drupal_modules
from detectors.generic_component_detector import detect_generic_components
from detectors.infra_detector import detect_infrastructure
from detectors.library_detector import detect_libraries
from detectors.plugin_detector import detect_wp_plugins
from detectors.security_detector import check_security
from detectors.stack_detector import detect_stack_signals
from services.passive_profile import (
    analyze_cookie_headers,
    build_transport_profile,
    group_stack_signals,
)
from services.recommendation_engine import generate_recommendations
from services.score_engine import calculate_score, risk_level
from services.version_service import (
    annotate_technology_stack,
    detect_cms_version,
    infer_primary_platform,
    recommended_cms_version,
)


def extract_assets(soup):
    """Collect public asset URLs that often reveal frameworks and plugins."""
    assets = []
    for tag in soup.find_all(["script", "link", "img"]):
        source = tag.get("src") or tag.get("href")
        if source:
            assets.append(source)
    return assets


def extract_meta_generator(soup):
    """Return the public generator meta tag when a site exposes one."""
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator:
        return (generator.get("content") or "").strip()
    return ""


def build_error_result(url: str, message: str):
    """Return a stable error payload so the UI can render gracefully."""
    return {
        "url": url,
        "final_url": url,
        "audit_method": "Built-in passive profiler",
        "platform_name": "No strong CMS fingerprint detected",
        "cms": "Scan could not confirm the platform",
        "cms_summary": "Scan could not confirm the platform",
        "cms_matches": [],
        "primary_cms": None,
        "secondary_cms": [],
        "version": "Not publicly exposed",
        "recommended_cms_version": "No CMS release track inferred",
        "fetch_warning": None,
        "plugins": [],
        "modules": [],
        "libraries": [],
        "technology_stack": [],
        "technology_profile": [],
        "security": [],
        "infra": [],
        "transport": [],
        "cookie_issues": [],
        "platform_label": "Platform Assessment",
        "component_label": "Modules / Extensions",
        "score": 0,
        "score_breakdown": [{"label": "Target fetch failed", "impact": -100}],
        "risk": "High",
        "recommendations": ["Verify the website is reachable and try the audit again."],
        "error": message,
    }


def run_scan(url):
    """Run the passive website audit and return a structured report."""
    try:
        html, headers, final_url, cookies, set_cookie_headers, fetch_warning = fetch_page(url)
    except Exception as exc:
        return build_error_result(url, str(exc))

    soup = BeautifulSoup(html, "html.parser")
    assets = extract_assets(soup)
    meta_generator = extract_meta_generator(soup)
    cms_profile = detect_cms_profile(html, headers, meta_generator, assets)
    cms = cms_profile["primary"]["name"] if cms_profile["primary"] else NO_CMS_MESSAGE

    plugins = detect_wp_plugins(html, headers, assets) if cms == "WordPress" else []
    if cms == "Drupal":
        modules = detect_drupal_modules(assets)
    elif cms != "WordPress":
        modules = detect_generic_components(html, headers, assets)
    else:
        modules = []
    libraries = detect_libraries(assets)
    technology_stack = detect_stack_signals(html, headers, assets, cookies, meta_generator)
    platform_name = infer_primary_platform(cms, technology_stack)
    version = detect_cms_version(html, headers, assets, meta_generator, platform_name)
    technology_stack = annotate_technology_stack(
        technology_stack,
        platform_name,
        version,
        libraries,
    )
    technology_profile = group_stack_signals(technology_stack)
    security = check_security(headers)
    infra = detect_infrastructure(headers)
    transport = build_transport_profile(final_url, headers)
    cookie_issues = analyze_cookie_headers(set_cookie_headers)

    if cms in {"WordPress", "Drupal"}:
        platform_label = "Detected CMS"
    elif cms_profile["matches"]:
        platform_label = "Detected CMS Stack"
    elif technology_stack:
        platform_label = "Primary Platform Signal"
    else:
        platform_label = "Platform Assessment"

    component_label = "WordPress Plugins" if cms == "WordPress" else "Modules / Extensions"

    scan = {
        "url": url,
        "final_url": final_url,
        "audit_method": "Built-in passive profiler",
        "platform_name": platform_name,
        "cms": cms,
        "cms_summary": cms_profile["summary"],
        "cms_matches": cms_profile["matches"],
        "primary_cms": cms_profile["primary"],
        "secondary_cms": cms_profile["secondary"],
        "version": version,
        "recommended_cms_version": recommended_cms_version(platform_name),
        "fetch_warning": fetch_warning,
        "plugins": plugins,
        "modules": modules,
        "libraries": libraries,
        "technology_stack": technology_stack,
        "technology_profile": technology_profile,
        "security": security,
        "infra": infra,
        "transport": transport,
        "cookie_issues": cookie_issues,
        "meta_generator": meta_generator,
        "cookies": cookies,
        "platform_label": platform_label,
        "component_label": component_label,
        "error": None,
    }
    scan["score"], scan["score_breakdown"] = calculate_score(scan)
    scan["risk"] = risk_level(scan["score"])
    scan["recommendations"] = generate_recommendations(scan)
    return scan
