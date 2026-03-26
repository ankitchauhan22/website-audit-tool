from __future__ import annotations

import requests
from requests import Request


MARKUP_VALIDATOR_URL = "https://validator.w3.org/nu/"


def validate_markup(url: str, timeout: int = 20) -> dict:
    """Validate a public page using the W3C HTML checker JSON output."""
    validator_url = Request("GET", MARKUP_VALIDATOR_URL, params={"doc": url, "out": "json"}).prepare().url
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
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        if status_code == 403:
            error_message = "W3C markup validation was blocked by the validator service (HTTP 403)."
        else:
            error_message = f"W3C markup validation could not be completed: {exc}"
        return {
            "checked": False,
            "error": error_message,
            "errors": 0,
            "warnings": 0,
            "messages": [],
            "items": [],
            "validator_url": validator_url,
        }

    messages = payload.get("messages", []) or []
    errors = [item for item in messages if item.get("type") == "error"]
    warnings = [item for item in messages if item.get("type") == "info" and item.get("subType") == "warning"]
    top_messages = []
    top_items = []
    for item in (errors + warnings)[:12]:
        text = (item.get("message") or "").strip()
        if text:
            top_messages.append(text)
            top_items.append(
                {
                    "type": "Error" if item.get("type") == "error" else "Warning",
                    "line": item.get("lastLine") or item.get("firstLine") or "",
                    "message": text,
                }
            )

    return {
        "checked": True,
        "error": None,
        "errors": len(errors),
        "warnings": len(warnings),
        "messages": top_messages,
        "items": top_items,
        "validator_url": validator_url,
    }
