from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import certifi
import requests


DEFAULT_ENDPOINTS = ("/wp-json", "/robots.txt", "/sitemap.xml", "/feed", "/rss.xml", "/user/login", "/administrator")
REQUEST_TIMEOUT = 8


@dataclass
class CollectedEvidence:
    url: str
    html: str
    headers: dict[str, str]
    assets: list[str]
    cookies: list[str]
    set_cookie_headers: list[str]
    meta_generator: str
    endpoint_results: dict[str, dict[str, Any]]
    js_globals: list[str]
    rendered_html: str


def collect_technology_evidence(
    url: str,
    html: str = "",
    headers: dict[str, Any] | None = None,
    assets: list[str] | None = None,
    cookies: list[str] | None = None,
    set_cookie_headers: list[str] | None = None,
    meta_generator: str = "",
    js_globals: list[str] | None = None,
    rendered_html: str = "",
    probe_endpoints: bool = True,
    endpoints: tuple[str, ...] = DEFAULT_ENDPOINTS,
    session: requests.Session | None = None,
) -> CollectedEvidence:
    return CollectedEvidence(
        url=url,
        html=html or "",
        headers={str(key): str(value) for key, value in (headers or {}).items()},
        assets=list(assets or []),
        cookies=list(cookies or []),
        set_cookie_headers=list(set_cookie_headers or []),
        meta_generator=meta_generator or "",
        endpoint_results=probe_common_endpoints(url, session=session, endpoints=endpoints) if probe_endpoints else {},
        js_globals=list(js_globals or []),
        rendered_html=rendered_html or "",
    )


def probe_common_endpoints(
    base_url: str,
    session: requests.Session | None = None,
    endpoints: tuple[str, ...] = DEFAULT_ENDPOINTS,
) -> dict[str, dict[str, Any]]:
    session = session or requests.Session()
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    if not parsed.scheme or not parsed.netloc:
        return {}

    normalized_base = f"{parsed.scheme}://{parsed.netloc}"
    results: dict[str, dict[str, Any]] = {}

    for endpoint in endpoints:
        target = urljoin(normalized_base, endpoint)
        try:
            response = session.get(
                target,
                timeout=REQUEST_TIMEOUT,
                headers={"Accept": "application/json, text/plain, application/xml;q=0.9, */*;q=0.8"},
                allow_redirects=True,
                verify=certifi.where(),
            )
            results[endpoint] = {
                "url": response.url,
                "status_code": response.status_code,
                "ok": response.ok,
                "body": (response.text or "")[:5000],
                "content_type": response.headers.get("Content-Type", ""),
                "headers": {str(key): str(value) for key, value in response.headers.items()},
            }
        except requests.RequestException as exc:
            results[endpoint] = {
                "url": target,
                "status_code": None,
                "ok": False,
                "body": "",
                "content_type": "",
                "headers": {},
                "error": str(exc),
            }

    return results

