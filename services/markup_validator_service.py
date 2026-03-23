from __future__ import annotations

import requests


MARKUP_VALIDATOR_URL = "https://validator.w3.org/nu/"


def validate_markup(url: str, timeout: int = 20) -> dict:
    """Validate a public page using the W3C HTML checker JSON output."""
    try:
        response = requests.get(
            MARKUP_VALIDATOR_URL,
            params={"doc": url, "out": "json"},
            headers={"User-Agent": "website-audit-tool/1.0", "Accept": "application/json"},
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        return {
            "checked": False,
            "error": f"W3C markup validation could not be completed: {exc}",
            "errors": 0,
            "warnings": 0,
            "messages": [],
        }

    messages = payload.get("messages", []) or []
    errors = [item for item in messages if item.get("type") == "error"]
    warnings = [item for item in messages if item.get("type") == "info" and item.get("subType") == "warning"]
    top_messages = []
    for item in (errors + warnings)[:5]:
        text = (item.get("message") or "").strip()
        if text:
            top_messages.append(text)

    return {
        "checked": True,
        "error": None,
        "errors": len(errors),
        "warnings": len(warnings),
        "messages": top_messages,
    }
