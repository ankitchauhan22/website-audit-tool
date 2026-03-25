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


def _meaningful_recommendations(items: list[dict]) -> list[dict]:
    severity_rank = {"must": 0, "high": 1, "monitor": 2}
    filtered = [item for item in items if item.get("severity") in {"must", "high"}]
    filtered.sort(key=lambda item: (severity_rank.get(item.get("severity", "monitor"), 3), item.get("title", "")))
    return filtered[:10]


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

    tls_validation = next((item for item in scan.get("transport", []) if item["check"] == "TLS Validation"), None)
    if tls_validation and tls_validation.get("value") in {"Certificate validation failed", "Expired", "Expiring soon"}:
        recommendations.append(
            _recommendation_item(
                "must" if tls_validation["value"] == "Certificate validation failed" else "high",
                "Repair TLS certificate trust",
                "Renew or reissue the certificate, install the full intermediate chain, and verify the certificate covers the production hostname and redirect target.",
                tls_validation.get("detail", "TLS validation needs review."),
            )
        )

    host_consistency = next((item for item in scan.get("domain_identity", []) if item["check"] == "Host Consistency"), None)
    if host_consistency and host_consistency.get("value") != "Aligned":
        recommendations.append(
            _recommendation_item(
                "high",
                "Review domain redirect and identity alignment",
                "Confirm the redirect target is intentional, branded correctly, monitored, and covered by the same certificate and DNS ownership controls as the requested domain.",
                host_consistency.get("detail", "Requested and resolved hosts were not fully aligned."),
            )
        )

    for cookie_issue in scan.get("cookie_issues", []):
        if not cookie_issue.get("is_insecure"):
            continue
        severity = cookie_issue.get("severity", "high")
        recommendations.append(
            _recommendation_item(
                severity,
                f"Harden cookie {cookie_issue['name']}",
                (
                    f"Set Secure, HttpOnly, and SameSite on '{cookie_issue['name']}'"
                    if cookie_issue.get("is_session_like")
                    else f"Review the cookie policy for '{cookie_issue['name']}' and add missing security attributes where compatible."
                ),
                f"{cookie_issue['issue']}. {cookie_issue.get('detail', '')}".strip(),
            )
        )

    for finding in scan.get("exposure_findings", []):
        recommendations.append(
            _recommendation_item(
                "high" if finding.get("severity") == "high" else "monitor",
                f"Reduce public leakage: {finding['name']}",
                "Remove unnecessary debug markers, comments, source maps, or internal environment references from production responses and rebuilt assets.",
                f"{finding.get('detail', '')} Evidence: {finding.get('evidence', 'Not captured')}. Source: {finding.get('source_url', 'Unknown page')}",
            )
        )

    reflected_probes = [item for item in scan.get("form_probes", []) if item.get("reflected_input")]
    errored_probes = [item for item in scan.get("form_probes", []) if item.get("server_error") or item.get("status_code") == "Request failed"]
    for item in reflected_probes:
        recommendations.append(
            _recommendation_item(
                "high",
                "Review reflected public form input",
                "Apply strict output encoding and input validation on the affected form workflow, then retest the response for reflection and error handling.",
                f"Probe action: {item.get('action')}. {item.get('detail')}",
            )
        )
    for item in errored_probes:
        recommendations.append(
            _recommendation_item(
                "high",
                "Stabilize public form handling",
                "Review validation, CSRF handling, and exception control on the affected POST handler so benign invalid input does not trigger unstable responses.",
                f"Probe action: {item.get('action')}. Result: {item.get('detail')}",
            )
        )

    performance = scan.get("performance_audit") or {}
    for strategy in ("mobile", "desktop"):
        audit = performance.get(strategy) or {}
        score = audit.get("score")
        if score is not None and score < 60:
            recommendations.append(
                _recommendation_item(
                    "high",
                    f"Improve {strategy} page speed",
                    f"Prioritize the highest-impact GTmetrix or provider opportunities for the {strategy} experience and retest after deployment.",
                    ", ".join(audit.get("recommendations", [])[:3]) or f"{strategy.title()} score: {score}",
                )
            )

    seo_issues = (scan.get("seo_audit") or {}).get("issues", [])
    for issue in seo_issues[:3]:
        recommendations.append(
            _recommendation_item(
                "high",
                "Fix SEO hygiene on key pages",
                "Correct the homepage metadata and template issues, then verify the same patterns across the public page set.",
                issue,
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
                    f"Public evidence did not expose the {stack_item['name']} version, so compare the product against the supported release track ({recommended}) using the CMS admin inventory, deployment manifest, package lock, or hosting asset register.",
                    f"Passive version checks already reviewed generator metadata, known asset paths, public script and stylesheet URLs, response headers, and exposed version query strings.",
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

    recommendations = _meaningful_recommendations(_dedupe_recommendations(recommendations))

    if not recommendations:
        recommendations.append(
            _recommendation_item(
                "high",
                "Review the site manually",
                "The scan did not find a clear high-confidence remediation item, so review key templates, critical forms, and the production asset inventory manually.",
                "Passive evidence did not surface a single dominant issue.",
            )
        )

    return recommendations
