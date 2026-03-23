from __future__ import annotations

from urllib.parse import urlparse

from bs4 import BeautifulSoup


def build_seo_audit(
    primary_html: str,
    pages: list[dict],
    markup_validation: dict | None = None,
    final_url: str = "",
    support_files: dict | None = None,
) -> dict:
    """Summarize a small set of practical SEO signals from the public page set."""
    soup = BeautifulSoup(primary_html or "", "html.parser")
    title = (soup.title.string.strip() if soup.title and soup.title.string else "")
    description_tag = soup.find("meta", attrs={"name": "description"})
    description = (description_tag.get("content") or "").strip() if description_tag else ""
    canonical_tag = None
    for link in soup.find_all("link", href=True):
        rel = link.get("rel") or []
        rel_values = [str(value).lower() for value in rel] if isinstance(rel, list) else [str(rel).lower()]
        if "canonical" in rel_values:
            canonical_tag = link
            break
    canonical = (canonical_tag.get("href") or "").strip() if canonical_tag else ""
    robots_tag = soup.find("meta", attrs={"name": "robots"})
    robots = (robots_tag.get("content") or "").strip() if robots_tag else ""
    viewport_tag = soup.find("meta", attrs={"name": "viewport"})
    viewport = (viewport_tag.get("content") or "").strip() if viewport_tag else ""
    structured_data_count = len(
        [
            tag
            for tag in soup.find_all("script", attrs={"type": lambda value: value and "ld+json" in value.lower()})
            if (tag.get_text() or "").strip()
        ]
    )
    h1_count = len(soup.find_all("h1"))
    h2_count = len(soup.find_all("h2"))
    internal_link_count = len(
        [
            link
            for link in soup.find_all("a", href=True)
            if (link.get("href") or "").strip() and not (link.get("href") or "").startswith(("http://", "https://", "mailto:", "tel:", "#"))
        ]
    )
    images = soup.find_all("img")
    missing_alt = sum(1 for image in images if not (image.get("alt") or "").strip())
    lang = ((soup.html or {}).get("lang") or "").strip() if soup.html else ""
    support_files = support_files or {}
    robots_txt_present = bool(support_files.get("robots_txt_present"))
    sitemap_present = bool(support_files.get("sitemap_present"))
    robots_disallow_all = bool(support_files.get("robots_disallow_all"))
    parsed_url = urlparse(final_url or "")
    path = (parsed_url.path or "/").strip("/")
    slug_segments = [segment for segment in path.split("/") if segment]
    url_is_clean = not parsed_url.query and all(segment.replace("-", "").isalnum() for segment in slug_segments)

    titles = []
    descriptions = []
    for page in pages:
        page_soup = BeautifulSoup(page.get("html", "") or "", "html.parser")
        page_title = page_soup.title.string.strip() if page_soup.title and page_soup.title.string else ""
        page_desc_tag = page_soup.find("meta", attrs={"name": "description"})
        page_desc = (page_desc_tag.get("content") or "").strip() if page_desc_tag else ""
        if page_title:
            titles.append(page_title)
        if page_desc:
            descriptions.append(page_desc)

    issues = []
    if not title:
        issues.append("Homepage title tag is missing.")
    elif len(title) < 20 or len(title) > 65:
        issues.append("Homepage title length looks weak for search snippets.")
    if not description:
        issues.append("Meta description is missing on the homepage.")
    elif len(description) < 70 or len(description) > 170:
        issues.append("Meta description length should be tightened.")
    if not canonical:
        issues.append("Canonical URL is not exposed on the homepage.")
    if robots and "noindex" in robots.lower():
        issues.append("Robots meta includes noindex.")
    if h1_count != 1:
        issues.append(f"Homepage exposes {h1_count} H1 tags.")
    if images and missing_alt:
        issues.append(f"{missing_alt} homepage image(s) are missing alt text.")
    if not lang:
        issues.append("HTML lang attribute is missing.")
    if len(set(titles)) < len(titles) and len(titles) > 1:
        issues.append("Duplicate page titles were found in the scanned page set.")
    if len(set(descriptions)) < len(descriptions) and len(descriptions) > 1:
        issues.append("Duplicate meta descriptions were found in the scanned page set.")
    if markup_validation:
        if markup_validation.get("errors"):
            issues.append(f"W3C markup validation reported {markup_validation['errors']} error(s).")
        if markup_validation.get("warnings"):
            issues.append(f"W3C markup validation reported {markup_validation['warnings']} warning(s).")

    seo_factors = []

    title_points = 5 if 50 <= len(title) <= 60 else 3 if title else 0
    seo_factors.append({"name": "Title Tag Optimization", "points": 5, "achieved": title_points, "detail": title or "Missing"})

    description_points = 3 if 120 <= len(description) <= 160 else 1 if description else 0
    seo_factors.append({"name": "Meta Description", "points": 3, "achieved": description_points, "detail": description or "Missing"})

    heading_points = 4 if h1_count == 1 and h2_count >= 1 else 2 if h1_count == 1 else 0
    seo_factors.append({"name": "Heading Structure", "points": 4, "achieved": heading_points, "detail": f"H1: {h1_count}, H2: {h2_count}"})

    if robots and "noindex" in robots.lower():
        indexability_points = 0
    elif robots_disallow_all:
        indexability_points = 0
    elif robots_txt_present:
        indexability_points = 5
    else:
        indexability_points = 3
    seo_factors.append({"name": "Indexability", "points": 5, "achieved": indexability_points, "detail": robots or "No robots meta"})

    sitemap_points = 3 if robots_txt_present and sitemap_present else 2 if robots_txt_present or sitemap_present else 0
    seo_factors.append({"name": "Sitemap + Robots.txt", "points": 3, "achieved": sitemap_points, "detail": f"robots.txt: {'yes' if robots_txt_present else 'no'}, sitemap: {'yes' if sitemap_present else 'no'}"})

    internal_link_points = 3 if internal_link_count >= 10 else 2 if internal_link_count >= 3 else 1 if internal_link_count > 0 else 0
    seo_factors.append({"name": "Internal Linking", "points": 3, "achieved": internal_link_points, "detail": f"{internal_link_count} internal link(s) on the homepage"})

    mobile_points = 4 if viewport else 0
    seo_factors.append({"name": "Mobile Friendliness", "points": 4, "achieved": mobile_points, "detail": viewport or "Viewport meta missing"})

    structured_points = 3 if structured_data_count > 0 else 0
    seo_factors.append({"name": "Structured Data (Schema)", "points": 3, "achieved": structured_points, "detail": f"{structured_data_count} JSON-LD block(s)"})

    alt_points = 2 if missing_alt == 0 else 1 if missing_alt <= 2 else 0
    seo_factors.append({"name": "Image Alt Tags", "points": 2, "achieved": alt_points, "detail": f"{missing_alt} image(s) missing alt text"})

    url_points = 3 if url_is_clean else 1 if parsed_url.path else 0
    seo_factors.append({"name": "URL Structure", "points": 3, "achieved": url_points, "detail": final_url or "Not available"})

    max_points = sum(item["points"] for item in seo_factors)
    achieved_points = sum(item["achieved"] for item in seo_factors)
    score = round((achieved_points / max_points) * 100) if max_points else 0

    return {
        "score": score,
        "achieved_points": achieved_points,
        "max_points": max_points,
        "factors": seo_factors,
        "title": title or "Not exposed",
        "meta_description": description or "Not exposed",
        "canonical": canonical or "Not exposed",
        "robots": robots or "Not exposed",
        "viewport": viewport or "Not exposed",
        "lang": lang or "Not exposed",
        "h1_count": h1_count,
        "h2_count": h2_count,
        "internal_link_count": internal_link_count,
        "structured_data_count": structured_data_count,
        "robots_txt_present": robots_txt_present,
        "sitemap_present": sitemap_present,
        "url_is_clean": url_is_clean,
        "images_missing_alt": missing_alt,
        "markup_validation": markup_validation or {"checked": False, "errors": 0, "warnings": 0, "messages": []},
        "issues": issues,
    }
