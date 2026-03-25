SECURITY_HEADERS = {
    "X-Frame-Options": "Clickjacking protection",
    "Content-Security-Policy": "Content Security Policy",
    "Strict-Transport-Security": "HSTS",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "Referrer policy",
}


def _evaluate_header(header: str, value: str) -> str:
    candidate = (value or "").strip().lower()
    if not candidate:
        return "FAIL"
    if header == "Content-Security-Policy":
        return "PASS" if "default-src" in candidate or "script-src" in candidate else "PARTIAL"
    if header == "Strict-Transport-Security":
        return "PASS" if "max-age=" in candidate and "includeSubDomains".lower() in candidate else "PARTIAL"
    if header == "X-Frame-Options":
        return "PASS" if candidate in {"deny", "sameorigin"} else "PARTIAL"
    if header == "X-Content-Type-Options":
        return "PASS" if "nosniff" in candidate else "PARTIAL"
    if header == "Referrer-Policy":
        return "PASS" if candidate in {"strict-origin-when-cross-origin", "same-origin", "no-referrer"} else "PARTIAL"
    return "PASS"


def check_security(headers):
    security = []

    for header, label in SECURITY_HEADERS.items():
        detected_value = headers.get(header) or headers.get(header.lower(), "")
        status = _evaluate_header(header, detected_value)
        is_present = bool(detected_value)
        security.append(
            {
                "header": header,
                "parameter": label,
                "detected": detected_value if is_present else "Missing",
                "recommended": "Enabled",
                "status": status,
            }
        )

    return security
