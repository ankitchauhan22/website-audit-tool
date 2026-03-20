def _factor(label: str, impact: int, severity: str, detail: str, action: str) -> dict:
    return {
        "label": label,
        "impact": impact,
        "severity": severity,
        "detail": detail,
        "action": action,
    }


def calculate_score(scan):
    score = 100
    breakdown = []

    if scan.get("error"):
        return 0, [
            _factor(
                "Target fetch failed",
                -100,
                "must",
                "The site could not be fetched reliably, so the audit could not verify any security or maintenance signals.",
                "Restore reachability, TLS trust, or bot-access compatibility, then rerun the audit.",
            )
        ]

    failed_headers = [item for item in scan["security"] if item["status"] == "FAIL"]
    if failed_headers:
        penalty = min(len(failed_headers) * 7, 35)
        score -= penalty
        breakdown.append(
            _factor(
                f"{len(failed_headers)} security headers missing",
                -penalty,
                "must",
                "Browser protections are incomplete, which increases exposure to clickjacking, MIME confusion, or content injection risks.",
                "Add the missing response headers and verify them in production responses.",
            )
        )
    else:
        breakdown.append(
            _factor(
                "Core security headers exposed",
                0,
                "good",
                "Key browser-side protection headers were visible in the public response.",
                "Keep header coverage consistent across all production routes.",
            )
        )

    https_item = next((item for item in scan.get("transport", []) if item["check"] == "HTTPS"), None)
    if https_item and https_item["value"] != "Enabled":
        score -= 15
        breakdown.append(
            _factor(
                "HTTPS not enforced",
                -15,
                "must",
                "Visitors can reach the site without strong transport security.",
                "Redirect HTTP to HTTPS and enable HSTS after validating certificate and redirect behavior.",
            )
        )

    cookie_issues = [item for item in scan.get("cookie_issues", []) if item["issue"] != "No obvious attribute gap in exposed header"]
    if cookie_issues:
        penalty = min(len(cookie_issues) * 3, 12)
        score -= penalty
        breakdown.append(
            _factor(
                f"{len(cookie_issues)} cookie security issues observed",
                -penalty,
                "high",
                "Some cookies were missing security attributes such as Secure, HttpOnly, or SameSite.",
                "Harden cookie flags on authentication and session cookies, then confirm with a fresh response capture.",
            )
        )

    if scan.get("meta_generator"):
        score -= 4
        breakdown.append(
            _factor(
                "Generator metadata exposed",
                -4,
                "monitor",
                "The site publicly exposes software identity metadata that can help fingerprint the stack.",
                "Minimize or remove version-identifying generator metadata where possible.",
            )
        )

    if len(scan["plugins"]) > 30:
        score -= 8
        breakdown.append(
            _factor(
                "Large WordPress plugin surface",
                -8,
                "high",
                "A large plugin footprint increases maintenance overhead and the chance of unpatched third-party exposure.",
                "Remove unused plugins and review the remaining plugin inventory against support and patch status.",
            )
        )

    if scan["cms"] != "WordPress" and len(scan["modules"]) > 30:
        score -= 8
        breakdown.append(
            _factor(
                "Large module or extension surface",
                -8,
                "high",
                "A large public component footprint increases patching effort and regression risk.",
                "Consolidate or remove unused extensions and review support status for the remaining components.",
            )
        )

    outdated_items = [
        item for item in scan.get("technology_stack", [])
        if item.get("status") in {"Outdated", "Deprecated"}
    ]
    if outdated_items:
        penalty = min(len(outdated_items) * 6, 24)
        score -= penalty
        breakdown.append(
            _factor(
                f"{len(outdated_items)} outdated or deprecated technologies detected",
                -penalty,
                "must",
                "Public version evidence shows at least part of the stack is behind a supported release line or already deprecated.",
                "Upgrade or replace the outdated technologies and retest the public assets after deployment.",
            )
        )

    unknown_versions = [
        item for item in scan.get("technology_stack", [])
        if item.get("detected_version") == "Not publicly exposed"
        and item.get("category") in {"CMS", "Commerce", "Frontend", "JavaScript Library", "Runtime"}
    ]
    if unknown_versions:
        breakdown.append(
            _factor(
                f"{len(unknown_versions)} technologies need internal version verification",
                0,
                "monitor",
                "Public evidence identified software families, but did not expose enough version data to prove patch status.",
                "Check internal package, plugin, and deployment inventories to confirm those versions are still supported.",
            )
        )

    score = max(score, 0)
    return score, breakdown


def risk_level(score):
    if score >= 85:
        return "Low"
    if score >= 60:
        return "Medium"
    return "High"
