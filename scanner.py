import hashlib

from bs4 import BeautifulSoup
from urllib.parse import urldefrag, urljoin, urlparse

from audit_tool.fetcher import fetch_page, fetch_text_asset, probe_post_forms
from detectors.cms_detector import NO_CMS_MESSAGE, detect_cms_profile
from detectors.drupal_detector import detect_drupal_modules
from detectors.generic_component_detector import detect_generic_components
from detectors.infra_detector import detect_infrastructure
from detectors.library_detector import detect_libraries
from detectors.leakage_detector import detect_public_leakage
from detectors.plugin_detector import detect_wp_plugins
from detectors.security_detector import check_security
from detectors.stack_detector import detect_stack_signals
from services.passive_profile import (
    analyze_cookie_headers,
    build_domain_identity_profile,
    build_transport_profile,
    fetch_tls_profile,
    group_stack_signals,
)
from services.pagespeed_service import run_pagespeed_audit
from services.recommendation_engine import generate_recommendations
from services.score_engine import calculate_score, risk_level
from services.markup_validator_service import validate_markup
from services.seo_service import build_seo_audit
from services.cve_service import enrich_libraries_with_cves
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


def _host_key(url: str) -> str:
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def extract_internal_links(soup, base_url: str, domain_key: str):
    """Collect same-domain HTML page links for bounded passive crawling."""
    links = []
    seen = set()

    for tag in soup.find_all("a", href=True):
        href = (tag.get("href") or "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue

        absolute = urljoin(base_url, href)
        absolute, _ = urldefrag(absolute)
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        if _host_key(absolute) != domain_key:
            continue
        if parsed.path.lower().endswith(
            (
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".svg",
                ".webp",
                ".pdf",
                ".zip",
                ".xml",
                ".rss",
                ".mp4",
                ".mp3",
                ".css",
                ".js",
                ".json",
            )
        ):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        links.append(absolute)

    return links


def _merge_named_items(*groups):
    merged = {}
    for group in groups:
        for item in group:
            name = (item.get("name") or "").lower()
            if not name:
                continue
            existing = merged.get(name)
            if not existing:
                merged[name] = dict(item)
                continue
            current_version = existing.get("detected_version")
            new_version = item.get("detected_version")
            if current_version in {None, "", "Not publicly exposed"} and new_version not in {None, "", "Not publicly exposed"}:
                existing["detected_version"] = new_version
            if existing.get("recommended_version") in {None, ""} and item.get("recommended_version"):
                existing["recommended_version"] = item["recommended_version"]
    return sorted(merged.values(), key=lambda item: item["name"].lower())


def _fetch_library_asset_bodies(assets: list[str], limit: int = 4) -> dict:
    bodies = {}
    for asset in assets:
        lowered = asset.lower()
        if not any(token in lowered for token in ("jquery", "bootstrap")):
            continue
        if len(bodies) >= limit:
            break
        try:
            bodies[asset] = fetch_text_asset(asset)
        except Exception:
            bodies[asset] = ""
    return bodies


def _inventory_forms(pages: list[dict], deep_scan: bool) -> list[dict]:
    """Collect public forms and explain whether they were eligible for probe review."""
    inventory = []
    seen = set()
    skip_keywords = {
        "login", "signin", "sign-in", "password", "checkout", "payment", "delete",
        "remove", "logout", "admin", "register", "account", "cart", "upload", "comment",
    }

    for page in pages:
        soup = BeautifulSoup(page.get("html", "") or "", "html.parser")
        page_url = page.get("final_url") or page.get("url") or ""
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").strip().lower() or "get"
            action = urljoin(page_url, form.get("action") or page_url)
            key = (page_url, action, method)
            if key in seen:
                continue
            seen.add(key)
            lowered_action = action.lower()
            field_names = [((field.get("name") or "")).lower() for field in form.find_all(["input", "select", "textarea"])]
            risky = any(keyword in lowered_action for keyword in skip_keywords) or any(
                any(keyword in name for keyword in skip_keywords) for name in field_names
            )

            if method != "post":
                status = "Observed only"
                note = "GET form detected; not eligible for POST probe."
            elif risky:
                status = "Skipped"
                note = "Form looked sensitive or state-changing, so probe was intentionally skipped."
            elif deep_scan:
                status = "Eligible"
                note = "Same-origin POST form matched the low-risk probe rules."
            else:
                status = "Observed only"
                note = "Deep scan was off, so POST probe was not attempted."

            inventory.append(
                {
                    "page_url": page_url,
                    "action": action,
                    "method": method.upper(),
                    "status": status,
                    "note": note,
                }
            )

    return inventory[:12]


def _fetch_seo_support_files(final_url: str) -> dict:
    parsed = urlparse(final_url)
    if not parsed.scheme or not parsed.netloc:
        return {"robots_txt_present": False, "sitemap_present": False, "robots_disallow_all": False}

    base = f"{parsed.scheme}://{parsed.netloc}"
    robots_url = urljoin(base, "/robots.txt")
    sitemap_url = urljoin(base, "/sitemap.xml")
    result = {"robots_txt_present": False, "sitemap_present": False, "robots_disallow_all": False}

    try:
        robots_text = fetch_text_asset(robots_url)
        if robots_text:
            result["robots_txt_present"] = True
            lowered = robots_text.lower()
            result["robots_disallow_all"] = "disallow: /" in lowered
            if "sitemap:" in lowered:
                result["sitemap_present"] = True
    except Exception:
        pass

    if not result["sitemap_present"]:
        try:
            sitemap_text = fetch_text_asset(sitemap_url)
            if sitemap_text and ("<urlset" in sitemap_text.lower() or "<sitemapindex" in sitemap_text.lower()):
                result["sitemap_present"] = True
        except Exception:
            pass

    return result


def _crawl_same_domain(start_url: str, initial_soup, max_pages: int = 8):
    """Fetch a bounded set of same-domain pages to widen passive evidence."""
    domain_key = _host_key(start_url)
    queue = extract_internal_links(initial_soup, start_url, domain_key)
    pages = []
    visited = {start_url}
    content_hashes = set()

    while queue and len(pages) + 1 < max_pages:
        next_url = queue.pop(0)
        if next_url in visited:
            continue
        visited.add(next_url)
        try:
            html, headers, final_url, cookies, set_cookie_headers, fetch_warning = fetch_page(next_url)
        except Exception as exc:
            pages.append(
                {
                    "url": next_url,
                    "final_url": next_url,
                    "error": str(exc),
                }
            )
            continue

        if _host_key(final_url) != domain_key:
            continue

        soup = BeautifulSoup(html, "html.parser")
        normalized_hash = hashlib.sha256(" ".join(html.split()).encode("utf-8", errors="ignore")).hexdigest()
        if normalized_hash in content_hashes:
            continue
        content_hashes.add(normalized_hash)
        pages.append(
            {
                "url": next_url,
                "final_url": final_url,
                "html": html,
                "headers": headers,
                "cookies": cookies,
                "set_cookie_headers": set_cookie_headers,
                "fetch_warning": fetch_warning,
                "assets": extract_assets(soup),
                "meta_generator": extract_meta_generator(soup),
            }
        )

        for discovered in extract_internal_links(soup, final_url, domain_key):
            if discovered not in visited and discovered not in queue and len(queue) + len(pages) < max_pages * 3:
                queue.append(discovered)

    return pages


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
        "domain_identity": [],
        "cookie_issues": [],
        "exposure_findings": [],
        "form_probes": [],
        "form_inventory": [],
        "crawl_summary": {
            "pages_scanned": 0,
            "pages_requested": 0,
            "pages_with_errors": 0,
            "coverage_note": "The scan stopped before any pages could be profiled.",
            "sampled_urls": [],
            "deep_scan_enabled": False,
        },
        "performance_audit": {"mobile": None, "desktop": None, "error": None},
        "seo_audit": {"issues": []},
        "website_details": {},
        "platform_label": "Platform Assessment",
        "component_label": "Modules / Extensions",
        "score": 0,
        "score_breakdown": [{"label": "Target fetch failed", "impact": -100}],
        "category_scores": {},
        "score_model": {},
        "risk": "High",
        "score_label": "Critical",
        "recommendations": ["Verify the website is reachable and try the audit again."],
        "error": message,
    }


def run_scan(url, deep_scan: bool = False):
    """Run the passive website audit and return a structured report."""
    try:
        html, headers, final_url, cookies, set_cookie_headers, fetch_warning = fetch_page(url)
    except Exception as exc:
        return build_error_result(url, str(exc))

    soup = BeautifulSoup(html, "html.parser")
    assets = extract_assets(soup)
    meta_generator = extract_meta_generator(soup)
    crawled_pages = _crawl_same_domain(final_url, soup) if deep_scan else []
    all_pages = [
        {
            "url": url,
            "final_url": final_url,
            "html": html,
            "headers": headers,
            "cookies": cookies,
            "set_cookie_headers": set_cookie_headers,
            "fetch_warning": fetch_warning,
            "assets": assets,
            "meta_generator": meta_generator,
        },
        *[page for page in crawled_pages if not page.get("error")],
    ]

    combined_html = "\n".join(page.get("html", "") for page in all_pages)
    combined_assets = sorted({asset for page in all_pages for asset in page.get("assets", [])})
    combined_cookies = sorted({cookie for page in all_pages for cookie in page.get("cookies", [])})
    combined_set_cookie_headers = [
        cookie_header
        for page in all_pages
        for cookie_header in page.get("set_cookie_headers", [])
    ]
    combined_generators = [page.get("meta_generator", "") for page in all_pages if page.get("meta_generator")]
    primary_generator = combined_generators[0] if combined_generators else meta_generator
    combined_header_lines = {}
    for page in all_pages:
        for key, value in page.get("headers", {}).items():
            existing = combined_header_lines.get(key)
            if not existing:
                combined_header_lines[key] = value
            elif value not in str(existing):
                combined_header_lines[key] = f"{existing} | {value}"

    cms_profile = detect_cms_profile(combined_html, combined_header_lines, primary_generator, combined_assets)
    cms = cms_profile["primary"]["name"] if cms_profile["primary"] else NO_CMS_MESSAGE

    plugins = detect_wp_plugins(combined_html, combined_header_lines, combined_assets) if cms == "WordPress" else []
    if cms == "Drupal":
        modules = detect_drupal_modules(combined_assets)
    elif cms != "WordPress":
        modules = detect_generic_components(combined_html, combined_header_lines, combined_assets)
    else:
        modules = []
    asset_bodies = _fetch_library_asset_bodies(combined_assets)
    libraries = detect_libraries(combined_assets, asset_bodies)
    libraries = enrich_libraries_with_cves(libraries)
    technology_stack = detect_stack_signals(combined_html, combined_header_lines, combined_assets, combined_cookies, primary_generator)
    platform_name = infer_primary_platform(cms, technology_stack)
    version = detect_cms_version(combined_html, combined_header_lines, combined_assets, primary_generator, platform_name)
    technology_stack = annotate_technology_stack(
        technology_stack,
        platform_name,
        version,
        libraries,
    )
    technology_profile = group_stack_signals(technology_stack)
    security = check_security(headers)
    infra = detect_infrastructure(headers)
    tls_profile = fetch_tls_profile(final_url)
    transport = build_transport_profile(final_url, headers, fetch_warning, tls_profile)
    domain_identity = build_domain_identity_profile(url, final_url, headers, tls_profile)
    cookie_issues = analyze_cookie_headers(combined_set_cookie_headers)
    exposure_findings = detect_public_leakage(all_pages)
    form_probes = probe_post_forms(final_url, all_pages) if deep_scan else []
    performance_audit = run_pagespeed_audit(final_url, html=html, assets=assets, headers=headers)
    markup_validation = validate_markup(final_url)
    seo_support_files = _fetch_seo_support_files(final_url)
    seo_audit = build_seo_audit(html, all_pages, markup_validation, final_url=final_url, support_files=seo_support_files)
    form_inventory = _inventory_forms(all_pages, deep_scan)
    plugins = _merge_named_items(plugins)
    modules = _merge_named_items(modules)
    crawl_errors = [page for page in crawled_pages if page.get("error")]
    sampled_urls = [page["final_url"] for page in all_pages[:10]]
    pages_scanned = len(all_pages)
    crawl_summary = {
        "pages_scanned": pages_scanned,
        "pages_requested": min(8, max(1, len(crawled_pages) + 1)),
        "pages_with_errors": len(crawl_errors),
        "coverage_note": (
            f"Passive crawl reviewed {pages_scanned} same-domain page(s) to widen technology, cookie, and security exposure."
            if deep_scan and pages_scanned > 1
            else "Deep scan is off, so only the landing page was assessed."
        ),
        "sampled_urls": sampled_urls,
        "deep_scan_enabled": deep_scan,
    }

    if cms in {"WordPress", "Drupal"}:
        platform_label = "Detected CMS"
    elif cms_profile["matches"]:
        platform_label = "Detected CMS Stack"
    elif technology_stack:
        platform_label = "Primary Platform Signal"
    else:
        platform_label = "Platform Assessment"

    component_label = "WordPress Plugins" if cms == "WordPress" else "Modules / Extensions"
    website_details = {
        "requested_url": url,
        "resolved_url": final_url,
        "resolved_hostname": urlparse(final_url).hostname or "Not resolved",
        "platform": platform_name,
        "cms_summary": cms_profile["summary"],
        "version": version,
        "recommended_track": recommended_cms_version(platform_name),
        "server": headers.get("Server", "Not exposed"),
        "meta_generator": primary_generator or "Not exposed",
        "deep_scan": "Enabled" if deep_scan else "Off",
        "pages_reviewed": pages_scanned,
        "pages_with_errors": len(crawl_errors),
        "components_detected": len(plugins) if cms == "WordPress" else len(modules),
        "libraries_detected": len(libraries),
        "cookies_observed": len(combined_cookies),
        "forms_reviewed": len(form_inventory),
        "forms_discovered": len(form_inventory),
    }

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
        "domain_identity": domain_identity,
        "cookie_issues": cookie_issues,
        "exposure_findings": exposure_findings,
        "form_probes": form_probes,
        "form_inventory": form_inventory,
        "performance_audit": performance_audit,
        "seo_audit": seo_audit,
        "website_details": website_details,
        "meta_generator": primary_generator,
        "cookies": combined_cookies,
        "crawl_summary": crawl_summary,
        "platform_label": platform_label,
        "component_label": component_label,
        "error": None,
    }
    scan["score"], scan["score_breakdown"], scan["category_scores"], scan["score_model"] = calculate_score(scan)
    scan["risk"] = risk_level(scan["score"])
    scan["score_label"] = scan["score_model"].get("benchmark_label", scan["risk"])
    scan["recommendations"] = generate_recommendations(scan)
    return scan
