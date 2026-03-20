def _recommendation_item(severity: str, title: str, action: str, evidence: str) -> dict:
    return {
        "severity": severity,
        "title": title,
        "action": action,
        "evidence": evidence,
    }


PASSIVE_VERSION_CHECKS = (
    "Passive version checks already reviewed generator metadata, asset and script URLs, version query strings, "
    "response headers, and known public platform paths."
)


def _dedupe_recommendations(items: list[dict]) -> list[dict]:
    seen = set()
    deduped = []
    for item in items:
        key = (item["severity"], item["title"], item["action"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def generate_recommendations(scan):
    """Generate prioritized remediation guidance from passive audit evidence."""
    recommendations = []
    platform_name = scan.get("platform_name") or scan["cms"]
    platform_version = scan.get("version") or "Not publicly exposed"
    recommended_track = scan.get("recommended_cms_version") or "No CMS release track inferred"

    if platform_name in {
        "WordPress",
        "Drupal",
        "Joomla",
        "Magento",
        "TYPO3",
        "Ghost",
        "Next.js",
        "Nuxt",
        "Vue.js",
        "Angular",
        "React",
    }:
        severity = "must" if platform_version not in {"", "Not publicly exposed"} else "high"
        action = (
            f"Update {platform_name} to the current supported track ({recommended_track}) and retest public assets "
            "after deployment."
            if platform_version not in {"", "Not publicly exposed"}
            else f"Confirm the live {platform_name} core version internally and align it with the current supported track ({recommended_track})."
        )
        recommendations.append(
            _recommendation_item(
                severity,
                f"Review {platform_name} core maintenance",
                action,
                f"Detected version: {platform_version}. Recommended track: {recommended_track}.",
            )
        )

    failed_security_headers = [item for item in scan.get("security", []) if item.get("status") == "FAIL"]
    if failed_security_headers:
        for item in failed_security_headers:
            recommendations.append(
                _recommendation_item(
                    "must",
                    f"Add {item['header']}",
                    f"Configure the {item['header']} response header to improve {item['parameter'].lower()}.",
                    f"Current exposure: {item['detected']}.",
                )
            )

    https_item = next((item for item in scan.get("transport", []) if item["check"] == "HTTPS"), None)
    if https_item and https_item["value"] != "Enabled":
        recommendations.append(
            _recommendation_item(
                "must",
                "Enforce HTTPS",
                "Redirect all HTTP traffic to HTTPS and enable HSTS after verifying certificate and redirect behavior.",
                "Final page load did not use HTTPS.",
            )
        )

    if scan.get("fetch_warning"):
        recommendations.append(
            _recommendation_item(
                "high",
                "Fix TLS certificate chain",
                "Repair the site's certificate chain or intermediate certificates so audits and browsers can validate TLS without fallback behavior.",
                scan["fetch_warning"],
            )
        )

    for plugin in scan.get("plugins", []):
        if plugin.get("detected_version") and plugin["detected_version"] != "Not publicly exposed":
            action = (
                f"Review plugin '{plugin['name']}' at version {plugin['detected_version']}, update it to the latest vendor-supported release, "
                "and remove it if it is no longer required."
            )
        else:
            action = (
                f"Review plugin '{plugin['name']}' in the site's admin or package inventory, then update or remove it if it is unsupported."
            )
        recommendations.append(
            _recommendation_item(
                "high",
                f"Review plugin {plugin['name']}",
                action,
                f"Public plugin fingerprint detected. Exposed version: {plugin.get('detected_version', 'Not publicly exposed')}. {PASSIVE_VERSION_CHECKS}",
            )
        )

    for module in scan.get("modules", []):
        if module.get("detected_version") and module["detected_version"] != "Not publicly exposed":
            action = (
                f"Review module or extension '{module['name']}' at version {module['detected_version']}, move it to a supported release, "
                "and remove unused components."
            )
        else:
            action = (
                f"Review module or extension '{module['name']}' in the platform admin or deployment inventory, then patch or retire it if unsupported."
            )
        recommendations.append(
            _recommendation_item(
                "high",
                f"Review component {module['name']}",
                action,
                f"Public component fingerprint detected. Exposed version: {module.get('detected_version', 'Not publicly exposed')}. {PASSIVE_VERSION_CHECKS}",
            )
        )

    if scan.get("meta_generator"):
        recommendations.append(
            _recommendation_item(
                "monitor",
                "Reduce generator metadata exposure",
                "Remove or minimize generator meta tags where that does not break site functionality.",
                f"Generator tag exposed: {scan['meta_generator']}.",
            )
        )

    for stack_item in scan.get("technology_stack", []):
        status = stack_item.get("status")
        recommended = stack_item.get("recommended_track") or "No structured release track"
        detected = stack_item.get("detected_version") or "Not publicly exposed"

        if status in {"Outdated", "Deprecated"}:
            recommendations.append(
                _recommendation_item(
                    "must",
                    f"Remediate {stack_item['name']} lifecycle risk",
                    f"Upgrade or replace {stack_item['name']} so it aligns with the supported release track ({recommended}).",
                    f"Observed status: {status}. Detected version: {detected}.",
                )
            )
        elif status == "Review":
            recommendations.append(
                _recommendation_item(
                    "high",
                    f"Review {stack_item['name']} release line",
                    f"Confirm whether {stack_item['name']} should stay on version {detected} or move to the current supported track ({recommended}).",
                    f"Observed status: Review.",
                )
            )
        elif status == "Observed" and detected == "Not publicly exposed":
            recommendations.append(
                _recommendation_item(
                    "monitor",
                    f"Validate {stack_item['name']} maintenance status",
                    f"Use the site's admin panel, deployment manifest, package lock, or hosting inventory to confirm the installed {stack_item['name']} version and compare it with the supported release track ({recommended}).",
                    f"Public version could not be confirmed after checking generator metadata, known asset paths, public script and stylesheet URLs, response headers, and exposed version query strings.",
                )
            )

        if stack_item["category"] in {"Analytics", "Marketing", "Tag Manager", "Consent"}:
            recommendations.append(
                _recommendation_item(
                    "monitor",
                    f"Review {stack_item['name']} business need",
                    f"Confirm the business, privacy, and consent requirements for {stack_item['name']} and document its data flow.",
                    f"Category: {stack_item['category']}.",
                )
            )
        if stack_item["category"] in {"Performance", "CDN", "Proxy"}:
            recommendations.append(
                _recommendation_item(
                    "monitor",
                    f"Validate {stack_item['name']} edge configuration",
                    f"Review caching, WAF, and proxy rules for {stack_item['name']} so they match the site's delivery and security requirements.",
                    f"Category: {stack_item['category']}.",
                )
            )

    if not recommendations:
        recommendations.append(
            _recommendation_item(
                "monitor",
                "Complete an internal maintenance review",
                "Compare the site's CMS, extensions, libraries, TLS settings, and security headers against your internal asset inventory and patch schedule.",
                "Passive checks did not surface urgent externally visible issues.",
            )
        )

    return _dedupe_recommendations(recommendations)
