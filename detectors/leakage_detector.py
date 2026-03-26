import re
from bs4 import BeautifulSoup, Comment

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)

LEAKAGE_PATTERNS = [
    {
        "name": "Source map reference exposed",
        "severity": "monitor",
        "pattern": re.compile(r"sourceMappingURL=.*?\.map", re.IGNORECASE),
        "detail": "Public JavaScript source map references can reveal original source structure and comments.",
    },
    {
        "name": "Debug or stack trace marker exposed",
        "severity": "high",
        "pattern": re.compile(r"(stack trace|traceback \(most recent call last\)|exception in thread|fatal error:)", re.IGNORECASE),
        "detail": "Debug traces in public responses can disclose internal paths, frameworks, or code behavior.",
    },
    {
        "name": "Cloud storage bucket reference exposed",
        "severity": "monitor",
        "pattern": re.compile(r"(s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net)", re.IGNORECASE),
        "detail": "Public cloud storage endpoints may reveal file-hosting patterns or unneeded infrastructure details.",
    },
    {
        "name": "Internal environment reference exposed",
        "severity": "high",
        "pattern": re.compile(r"\b(staging|dev|qa|internal|test environment|sandbox)\b", re.IGNORECASE),
        "detail": "References to internal environments in public responses can expose operational details that should stay private.",
    },
]


def detect_public_leakage(pages: list[dict]) -> list[dict]:
    """Inspect crawled HTML for public leakage markers with conservative evidence rules."""
    findings = []
    seen = set()

    for page in pages:
        html = page.get("html", "") or ""
        page_url = page.get("final_url") or page.get("url") or "Unknown page"
        soup = BeautifulSoup(html, "html.parser")

        email_match = EMAIL_PATTERN.search(html)
        if email_match:
            evidence = email_match.group(0)
            key = ("Email address exposure", evidence.lower())
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "name": "Email address exposure",
                        "severity": "monitor",
                        "detail": "Public email addresses can increase spam, phishing, and contact-enumeration risk when they are exposed directly in page source.",
                        "evidence": evidence,
                        "source_url": page_url,
                    }
                )

        for pattern in LEAKAGE_PATTERNS:
            match = pattern["pattern"].search(html)
            if not match:
                continue
            evidence = " ".join(match.group(0).split())[:120]
            key = (pattern["name"], evidence)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "name": pattern["name"],
                    "severity": pattern["severity"],
                    "detail": pattern["detail"],
                    "evidence": evidence,
                    "source_url": page_url,
                }
            )

        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = " ".join(str(comment).split())
            if not comment_text:
                continue
            lowered = comment_text.lower()
            if not any(token in lowered for token in ("password", "secret", "token", "internal", "staging", "todo", "debug")):
                continue
            evidence = comment_text[:120]
            key = ("Sensitive HTML comment exposed", evidence)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "name": "Sensitive HTML comment exposed",
                    "severity": "high",
                    "detail": "HTML comments exposed internal notes or sensitive implementation hints in public markup.",
                    "evidence": evidence,
                    "source_url": page_url,
                }
            )

        inline_scripts = soup.find_all("script")
        for script in inline_scripts:
            body = script.string or script.get_text(" ", strip=True)
            if not body:
                continue
            if re.search(r"(api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]", body, re.IGNORECASE):
                evidence = "Inline script exposes configuration-like token naming."
                key = ("Potential client-side secret reference", page_url)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {
                        "name": "Potential client-side secret reference",
                        "severity": "high",
                        "detail": "Inline JavaScript appears to expose token or secret-like configuration keys in public markup.",
                        "evidence": evidence,
                        "source_url": page_url,
                    }
                )

    return findings
