from __future__ import annotations

import requests


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _library_keywords(name: str, version: str) -> str | None:
    normalized = (name or "").lower()
    major_minor = ".".join((version or "").split(".")[:2]) if version and version != "Not publicly exposed" else ""
    if normalized == "jquery" and major_minor:
        return f"jQuery {major_minor}"
    if normalized == "jquery ui" and major_minor:
        return f"jQuery UI {major_minor}"
    if normalized == "bootstrap" and major_minor:
        return f"Bootstrap {major_minor}"
    if normalized == "core-js" and major_minor:
        return f"core-js {major_minor}"
    if normalized == "swiper" and major_minor:
        return f"Swiper {major_minor}"
    return None


def enrich_libraries_with_cves(libraries: list[dict], timeout: int = 12) -> list[dict]:
    """Attach a small current-CVE summary from NVD when library version evidence is usable."""
    enriched = []
    for library in libraries:
        enriched_item = dict(library)
        enriched_item["cves"] = []
        enriched_item["cve_summary"] = "No CVE lookup performed"
        version = library.get("detected_version")
        keywords = _library_keywords(library.get("name", ""), version)
        if not keywords:
            enriched.append(enriched_item)
            continue

        try:
            response = requests.get(
                NVD_CVE_API,
                params={
                    "keywordSearch": keywords,
                    "keywordExactMatch": "",
                    "resultsPerPage": 3,
                },
                timeout=timeout,
                headers={"User-Agent": "website-audit-tool/1.0"},
            )
            response.raise_for_status()
            payload = response.json()
            vulnerabilities = payload.get("vulnerabilities", []) or []
            cves = []
            for item in vulnerabilities[:3]:
                cve = item.get("cve", {})
                descriptions = cve.get("descriptions", []) or []
                description = next((entry.get("value") for entry in descriptions if entry.get("lang") == "en"), "No description")
                cves.append(
                    {
                        "id": cve.get("id", "Unknown CVE"),
                        "description": description[:180],
                    }
                )
            enriched_item["cves"] = cves
            enriched_item["cve_summary"] = f"{len(cves)} potential NVD CVE match(es) found" if cves else "No quick NVD CVE match found"
        except requests.RequestException:
            enriched_item["cve_summary"] = "NVD CVE lookup unavailable"

        enriched.append(enriched_item)

    return enriched
