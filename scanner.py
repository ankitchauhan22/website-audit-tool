import hashlib

from bs4 import BeautifulSoup
from urllib.parse import urldefrag, urljoin, urlparse

from audit_tool.fetcher import fetch_page, fetch_text_asset, probe_post_forms
from core.collector import collect_technology_evidence
from core.detector import detect_technology_profile
from core.enricher import enrich_scan_technology, enrich_with_cves
from core.scorer import calculate_audit_scores as calculate_score
from core.scorer import risk_level
from detectors.cms_detector import NO_CMS_MESSAGE, detect_cms_profile
from detectors.drupal_detector import detect_drupal_modules
from detectors.generic_component_detector import detect_generic_components
from detectors.infra_detector import detect_infrastructure
from detectors.library_detector import detect_libraries
from detectors.leakage_detector import detect_public_leakage
from detectors.plugin_detector import detect_wp_plugins
from detectors.security_detector import check_security
from services.passive_profile import (
    analyze_cookie_headers,
    build_domain_identity_profile,
    build_transport_profile,
    fetch_tls_profile,
    group_stack_signals,
)
from services.pagespeed_service import run_pagespeed_audit
from services.recommendation_engine import generate_recommendations
from services.markup_validator_service import validate_markup
from services.seo_service import build_seo_audit
from services.external_enrichment_service import fetch_external_technology_enrichment


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


def _merge_stack_items(*groups):
    merged = {}
    for group in groups:
        for item in group:
            key = _canonical_key(item.get("name", ""))
            if not key:
                continue
            existing = merged.get(key)
            if not existing:
                merged[key] = dict(item)
                continue
            if item.get("confidence_score", 0) > existing.get("confidence_score", 0):
                merged[key] = dict(item)
                continue
            if item.get("evidence") and item["evidence"] not in str(existing.get("evidence", "")):
                existing["evidence"] = ", ".join(filter(None, [existing.get("evidence"), item.get("evidence")]))
    return sorted(merged.values(), key=lambda item: (-item.get("confidence_score", 0), item.get("name", "").lower()))


def _stack_items_from_tech_detection(technology_detection: dict) -> list[dict]:
    items = []
    category_map = {
        "Blogs": "CMS",
        "Framework": "Frontend",
        "Frontend": "Frontend",
        "JavaScript Library": "JavaScript Library",
        "Analytics": "Analytics",
        "Marketing": "Marketing",
        "Tag Manager": "Tag Manager",
        "Hosting": "Hosting",
        "Infrastructure": "Hosting",
        "CDN": "CDN",
        "Proxy": "Proxy",
        "Runtime": "Runtime",
        "Commerce": "Commerce",
        "Headless CMS": "CMS",
        "CMS": "CMS",
    }
    for item in technology_detection.get("technologies", []):
        category = next((category_map.get(category) for category in item.get("categories", []) if category_map.get(category)), "Technology")
        items.append(
            {
                "category": category,
                "name": item["name"],
                "confidence": item.get("confidence", "Low"),
                "confidence_score": round((item.get("confidence_score", 0) or 0) * 10, 1),
                "confidence_score_10": item.get("confidence_score", 0),
                "evidence": ", ".join(item.get("signals", [])[:3]) or "Pattern-based technology match",
                "detected_version": item.get("detected_version", "Not publicly exposed"),
                "source": "public",
            }
        )
    return items


def _cms_profile_from_technology_detection(technology_detection: dict) -> dict:
    technologies = technology_detection.get("technologies", [])
    cms_candidates = [item for item in technologies if item.get("category") in {"CMS", "Commerce", "Headless CMS"}]
    if not cms_candidates:
        return {"primary": None, "secondary": [], "matches": [], "summary": NO_CMS_MESSAGE}

    matches = []
    for index, item in enumerate(cms_candidates[:3]):
        matches.append(
            {
                "name": item["name"],
                "family": item.get("category", "Technology"),
                "role": "Primary" if index == 0 else "Secondary",
                "confidence": item.get("confidence", "Low"),
                "signals": item.get("signals", [])[:5],
                "source": "public",
            }
        )
    primary = matches[0]
    summary = "; ".join(
        f"{item['name']} ({item['role'].lower()}, {item['family'].lower()}, {str(item['confidence']).lower()} confidence)"
        for item in matches
    )
    return {"primary": primary, "secondary": matches[1:], "matches": matches, "summary": summary}


def _canonical_key(value: str) -> str:
    return "".join(character for character in (value or "").lower() if character.isalnum())


def _merge_external_named_items(local_items, external_items, kind: str):
    merged = {}
    for item in local_items:
        enriched = dict(item)
        enriched.setdefault("confidence", "High")
        enriched.setdefault("evidence", "Public evidence from scanned pages and assets.")
        enriched.setdefault("source", "public")
        merged[_canonical_key(enriched.get("name", ""))] = enriched

    for item in external_items:
        key = _canonical_key(item.get("name", ""))
        if not key:
            continue
        existing = merged.get(key)
        if existing:
            if existing.get("detected_version") in {None, "", "Not publicly exposed"} and item.get("detected_version") not in {None, "", "Not publicly exposed"}:
                existing["detected_version"] = item["detected_version"]
            existing["source"] = "merged"
            existing["confidence"] = existing.get("confidence") or item.get("confidence", "Medium")
            if item.get("evidence"):
                existing["evidence"] = (
                    existing.get("evidence", "Public evidence from scanned pages and assets.")
                    + f" Refined with {item['evidence'].lower()}."
                )
            continue

        external_copy = dict(item)
        external_copy["confidence"] = item.get("confidence", "Low")
        external_copy["source"] = "external"
        external_copy["evidence"] = item.get("evidence", f"External enrichment for {kind}.")
        merged[key] = external_copy

    return sorted(merged.values(), key=lambda item: item["name"].lower())


def _evidence_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _build_profile_snapshot(platform_name: str, cms_profile: dict, technology_stack: list[dict], plugins: list[dict], modules: list[dict], libraries: list[dict]) -> dict:
    primary_match = cms_profile.get("primary") or {}
    secondary_matches = cms_profile.get("secondary") or []
    confidence = primary_match.get("confidence")
    if not confidence:
        stack_confidence_scores = {"High": 3, "Medium": 2, "Low": 1}
        top_stack = sorted(
            technology_stack,
            key=lambda item: (-item.get("confidence_score", 0), -stack_confidence_scores.get(item.get("confidence", "Low"), 1)),
        )
        confidence = top_stack[0].get("confidence") if top_stack else "Low"

    primary_evidence = []
    primary_evidence.extend(_evidence_list(primary_match.get("signals")))
    primary_evidence.extend(
        item.get("evidence", "")
        for item in technology_stack
        if item.get("name") == platform_name and item.get("evidence")
    )
    primary_evidence = list(dict.fromkeys(filter(None, primary_evidence)))[:5]

    component_items = plugins if platform_name == "WordPress" else modules
    component_names = {item.get("name") for item in component_items}
    library_names = {item.get("name") for item in libraries}
    secondary_names = {item.get("name") for item in secondary_matches}
    supporting_stack = [
        item for item in technology_stack
        if item.get("name") != platform_name
        and item.get("name") not in component_names
        and item.get("name") not in library_names
        and item.get("name") not in secondary_names
        and item.get("category") not in {"CMS", "Blogs", "JavaScript Library", "Database"}
    ]
    supporting_stack = sorted(
        supporting_stack,
        key=lambda item: (-item.get("confidence_score", 0), item.get("name", "").lower()),
    )[:8]

    component_confident = [item for item in component_items if item.get("source") != "external" or item.get("detected_version") != "Not publicly exposed"]
    library_confident = [item for item in libraries if item.get("source") != "external" or item.get("detected_version") != "Not publicly exposed"]

    return {
        "primary_platform": platform_name,
        "primary_confidence": confidence or "Low",
        "primary_evidence": primary_evidence,
        "secondary_platforms": secondary_matches[:4],
        "supporting_stack": supporting_stack,
        "component_count": len(component_confident),
        "library_count": len(library_confident),
        "component_source_summary": {
            "public": sum(1 for item in component_items if item.get("source") == "public"),
            "merged": sum(1 for item in component_items if item.get("source") == "merged"),
            "external": sum(1 for item in component_items if item.get("source") == "external"),
        },
        "library_source_summary": {
            "public": sum(1 for item in libraries if item.get("source") == "public"),
            "merged": sum(1 for item in libraries if item.get("source") == "merged"),
            "external": sum(1 for item in libraries if item.get("source") == "external"),
        },
    }


def _fetch_library_asset_bodies(assets: list[str], limit: int = 14) -> dict:
    bodies = {}
    library_tokens = (
        "jquery",
        "bootstrap",
        "swiper",
        "lazysizes",
        "core-js",
        "aos",
        "underscore",
        "clipboard",
        "owl",
        "carousel",
        "a11y",
        "vendor",
        "bundle",
        "chunk",
        "slider",
        "lazy",
        "gallery",
        "animation",
        "core",
        "ui",
    )
    for asset in assets:
        lowered = asset.lower()
        is_text_asset = lowered.endswith((".js", ".css")) or ".js?" in lowered or ".css?" in lowered
        if not is_text_asset:
            continue
        if not any(token in lowered for token in library_tokens) and len(bodies) >= max(6, limit // 2):
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
            has_file_upload = bool(form.find("input", attrs={"type": lambda value: value and value.lower() == "file"}))
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

            if has_file_upload:
                status = "Review needed"
                note = "File upload input detected; validate file type, size, malware scanning, and storage controls."

            inventory.append(
                {
                    "page_url": page_url,
                    "action": action,
                    "method": method.upper(),
                    "status": status,
                    "note": note,
                    "has_file_upload": has_file_upload,
                }
            )

    return inventory[:12]


def _fetch_seo_support_files(final_url: str) -> dict:
    parsed = urlparse(final_url)
    if not parsed.scheme or not parsed.netloc:
        return {
            "robots_txt_present": False,
            "sitemap_present": False,
            "robots_disallow_all": False,
            "robots_sensitive_paths": [],
            "security_txt_present": False,
            "security_txt_url": "",
        }

    base = f"{parsed.scheme}://{parsed.netloc}"
    robots_url = urljoin(base, "/robots.txt")
    sitemap_url = urljoin(base, "/sitemap.xml")
    result = {
        "robots_txt_present": False,
        "sitemap_present": False,
        "robots_disallow_all": False,
        "robots_sensitive_paths": [],
        "security_txt_present": False,
        "security_txt_url": "",
    }

    try:
        robots_text = fetch_text_asset(robots_url)
        if robots_text:
            result["robots_txt_present"] = True
            lowered = robots_text.lower()
            result["robots_disallow_all"] = "disallow: /" in lowered
            sensitive_paths = []
            for line in robots_text.splitlines():
                stripped = line.strip()
                lowered_line = stripped.lower()
                if not lowered_line.startswith("disallow:"):
                    continue
                if any(token in lowered_line for token in ("/admin", "/administrator", "/backup", "/private", "/internal", "/upload", "/staging")):
                    sensitive_paths.append(stripped)
            result["robots_sensitive_paths"] = sensitive_paths[:5]
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

    for security_path in ("/.well-known/security.txt", "/security.txt"):
        try:
            security_text = fetch_text_asset(urljoin(base, security_path))
            if security_text and ("contact:" in security_text.lower() or "expires:" in security_text.lower()):
                result["security_txt_present"] = True
                result["security_txt_url"] = urljoin(base, security_path)
                break
        except Exception:
            continue

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
        "technology_detection": {"technologies": [], "by_name": {}, "endpoint_probes": {}},
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
        "technology_snapshot": {},
        "platform_label": "Platform Assessment",
        "component_label": "Modules / Extensions",
        "score": 0,
        "score_breakdown": [{"label": "Target fetch failed", "impact": -100}],
        "category_scores": {"technology_health": 0, "security": 0, "performance": 0, "seo": 0},
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
    evidence = collect_technology_evidence(
        url=final_url,
        html=combined_html,
        headers=combined_header_lines,
        assets=combined_assets,
        cookies=combined_cookies,
        set_cookie_headers=combined_set_cookie_headers,
        meta_generator=primary_generator,
        probe_endpoints=True,
    )
    endpoint_probes = evidence.endpoint_results
    evidence.endpoint_results = endpoint_probes
    technology_detection = detect_technology_profile(evidence)
    external_enrichment = fetch_external_technology_enrichment(final_url)

    cms_profile = _cms_profile_from_technology_detection(technology_detection)
    legacy_cms_profile = detect_cms_profile(combined_html, combined_header_lines, primary_generator, combined_assets)
    if not cms_profile["matches"]:
        cms_profile = legacy_cms_profile
    if not cms_profile["matches"] and external_enrichment.get("cms"):
        for item in external_enrichment["cms"][:2]:
            cms_profile["matches"].append(
                {
                    "name": item["name"],
                    "family": "Externally enriched CMS hint",
                    "role": "Secondary",
                    "confidence": item.get("confidence", "Low"),
                    "signals": [item.get("evidence", "External enrichment from technologychecker.io")],
                    "source": "external",
                }
            )
        cms_profile["summary"] = "Local scan did not confirm a CMS; external enrichment added low-confidence platform hints."
    cms = cms_profile["primary"]["name"] if cms_profile["primary"] else NO_CMS_MESSAGE

    plugins = detect_wp_plugins(combined_html, combined_header_lines, combined_assets) if cms == "WordPress" else []
    if cms == "Drupal":
        modules = detect_drupal_modules(combined_assets)
    elif cms != "WordPress":
        modules = detect_generic_components(combined_html, combined_header_lines, combined_assets)
    else:
        modules = []
    asset_bodies = _fetch_library_asset_bodies(combined_assets)
    libraries = detect_libraries(combined_assets, asset_bodies, combined_html)
    libraries = enrich_with_cves(libraries)
    technology_stack = _merge_stack_items(_stack_items_from_tech_detection(technology_detection))
    enrichment_seed = {
        "cms": cms,
        "technology_stack": technology_stack,
        "libraries": libraries,
        "plugins": plugins,
        "modules": modules,
        "combined_html": combined_html,
        "combined_headers": combined_header_lines,
        "combined_assets": combined_assets,
        "meta_generator": primary_generator,
    }
    enriched_technology = enrich_scan_technology(enrichment_seed)
    platform_name = enriched_technology["platform_name"]
    version = enriched_technology["version"]
    libraries = enriched_technology["libraries"]
    technology_stack = enriched_technology["technology_stack"]
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
    plugins = _merge_external_named_items(_merge_named_items(plugins), external_enrichment.get("plugins", []), "plugins")
    modules = _merge_external_named_items(_merge_named_items(modules), external_enrichment.get("frameworks", []), "frameworks")
    libraries = _merge_external_named_items(libraries, external_enrichment.get("libraries", []), "libraries")
    technology_snapshot = _build_profile_snapshot(platform_name, cms_profile, technology_stack, plugins, modules, libraries)
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
        "platform_confidence": technology_snapshot["primary_confidence"],
        "version": version,
        "recommended_track": enriched_technology["recommended_version"],
        "recommended_track_source": enriched_technology["recommended_source"],
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
        "primary_evidence": technology_snapshot["primary_evidence"],
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
        "recommended_cms_version": enriched_technology["recommended_version"],
        "recommended_cms_source": enriched_technology["recommended_source"],
        "fetch_warning": fetch_warning,
        "plugins": plugins,
        "modules": modules,
        "libraries": libraries,
        "technology_detection": technology_detection,
        "technology_stack": technology_stack,
        "technology_profile": technology_profile,
        "technology_snapshot": technology_snapshot,
        "security": security,
        "security_txt": {
            "present": bool(seo_support_files.get("security_txt_present")),
            "url": seo_support_files.get("security_txt_url", ""),
        },
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
        "technology_snapshot": technology_snapshot,
        "meta_generator": primary_generator,
        "cookies": combined_cookies,
        "crawl_summary": crawl_summary,
        "platform_label": platform_label,
        "component_label": component_label,
        "external_enrichment": external_enrichment,
        "error": None,
    }
    scan["score"], scan["score_breakdown"], scan["category_scores"], scan["score_model"] = calculate_score(scan)
    scan["risk"] = risk_level(scan["score"])
    scan["score_label"] = scan["score_model"].get("benchmark_label", scan["risk"])
    scan["recommendations"] = generate_recommendations(scan)
    return scan
