SECURITY_HEADERS = {
    "X-Frame-Options": "Clickjacking protection",
    "Content-Security-Policy": "Content Security Policy",
    "Strict-Transport-Security": "HSTS",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "Referrer policy",
}


def check_security(headers):
    security = []

    for header, label in SECURITY_HEADERS.items():
        is_present = header in headers
        security.append(
            {
                "header": header,
                "parameter": label,
                "detected": "Enabled" if is_present else "Missing",
                "recommended": "Enabled",
                "status": "PASS" if is_present else "FAIL",
            }
        )

    return security
