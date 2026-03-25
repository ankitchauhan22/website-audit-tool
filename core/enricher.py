from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from services.version_service import (
    annotate_technology_stack,
    detect_cms_version,
    infer_primary_platform,
    recommended_cms_source,
    recommended_cms_version,
)


CVE_MAP_PATH = Path(__file__).resolve().parent.parent / "data" / "cve_map.json"


@lru_cache(maxsize=1)
def _load_cve_map() -> dict:
    if not CVE_MAP_PATH.exists():
        return {}
    return json.loads(CVE_MAP_PATH.read_text(encoding="utf-8"))


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version or ""))


def _compare_versions(left: str, right: str) -> int:
    left_key = _version_key(left)
    right_key = _version_key(right)
    width = max(len(left_key), len(right_key), 1)
    left_key += (0,) * (width - len(left_key))
    right_key += (0,) * (width - len(right_key))
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def _matches_constraint(version: str, constraint: str) -> bool:
    if not version or version == "Not publicly exposed":
        return False
    constraint = (constraint or "").strip()
    if not constraint:
        return False
    if constraint.endswith(".x"):
        return version.startswith(constraint[:-2] + ".") or version == constraint[:-2]
    for operator in ("<=", ">=", "<", ">", "=="):
        if constraint.startswith(operator):
            target = constraint[len(operator):].strip()
            cmp = _compare_versions(version, target)
            return {
                "<": cmp < 0,
                "<=": cmp <= 0,
                ">": cmp > 0,
                ">=": cmp >= 0,
                "==": cmp == 0,
            }[operator]
    return version.startswith(constraint)


def enrich_with_cves(items: list[dict]) -> list[dict]:
    cve_map = _load_cve_map()
    enriched = []
    for item in items or []:
        copy = dict(item)
        name = copy.get("name")
        version = copy.get("detected_version")
        matches = []
        for entry in cve_map.get(name, []):
            if _matches_constraint(version, entry.get("constraint", "")):
                matches.append(
                    {
                        "id": entry["id"],
                        "severity": entry.get("severity", "Unknown"),
                        "description": entry.get("description", "")[:180],
                    }
                )
        copy["cves"] = matches
        copy["cve_summary"] = f"{len(matches)} mapped CVE(s)" if matches else "No mapped CVE found"
        enriched.append(copy)
    return enriched


def enrich_scan_technology(scan: dict) -> dict:
    platform_name = infer_primary_platform(scan.get("cms"), scan.get("technology_stack", []))
    version = detect_cms_version(
        scan.get("combined_html", ""),
        scan.get("combined_headers", {}),
        scan.get("combined_assets", []),
        scan.get("meta_generator", ""),
        platform_name,
    )
    libraries = enrich_with_cves(scan.get("libraries", []))
    technology_stack = annotate_technology_stack(scan.get("technology_stack", []), platform_name, version, libraries)
    return {
        "platform_name": platform_name,
        "version": version,
        "recommended_version": recommended_cms_version(platform_name),
        "recommended_source": recommended_cms_source(platform_name),
        "libraries": libraries,
        "technology_stack": technology_stack,
    }

