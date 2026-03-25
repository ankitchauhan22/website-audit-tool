from __future__ import annotations

import shutil
import subprocess
import tempfile
from email.parser import Parser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import certifi
import requests
from bs4 import BeautifulSoup


DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
        "image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1",
}

MOBILE_HEADERS = {
    **DEFAULT_HEADERS,
    "User-Agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.4 Mobile/15E148 Safari/604.1"
    ),
}

FALLBACK_HEADERS = [DEFAULT_HEADERS, MOBILE_HEADERS]
TLS_CA_BUNDLE = certifi.where()


def normalize_url(url: str) -> str:
    """Normalize and validate a user-supplied URL."""
    candidate = (url or "").strip()
    if not candidate:
        raise ValueError("A website URL is required.")

    parsed = urlparse(candidate)
    if not parsed.scheme:
        candidate = f"https://{candidate}"
        parsed = urlparse(candidate)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    return candidate


def _set_cookie_headers_from_response(response: requests.Response) -> list[str]:
    """Extract all Set-Cookie headers from a requests response."""
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers and hasattr(raw_headers, "get_all"):
        return list(raw_headers.get_all("Set-Cookie"))
    if response.headers.get("Set-Cookie"):
        return [response.headers["Set-Cookie"]]
    return []


def _fetch_with_requests(
    session: requests.Session,
    url: str,
    timeout: int,
    verify,
) -> tuple[str, requests.structures.CaseInsensitiveDict, str, list[str], list[str]]:
    """Fetch a page using requests with browser-like header rotation."""
    last_error = None

    for candidate_headers in FALLBACK_HEADERS:
        try:
            response = session.get(
                url,
                timeout=timeout,
                headers=candidate_headers,
                allow_redirects=True,
                verify=verify,
            )
            response.raise_for_status()
            response_headers = requests.structures.CaseInsensitiveDict(response.headers)
            version = getattr(response.raw, "version", None)
            if version == 20:
                response_headers["X-Audit-HTTP-Version"] = "HTTP/2"
            elif version == 11:
                response_headers["X-Audit-HTTP-Version"] = "HTTP/1.1"
            elif version == 10:
                response_headers["X-Audit-HTTP-Version"] = "HTTP/1.0"
            return (
                response.text,
                response_headers,
                response.url,
                list(response.cookies.keys()),
                _set_cookie_headers_from_response(response),
            )
        except requests.HTTPError as exc:
            last_error = exc
            if exc.response is not None and exc.response.status_code != 403:
                break
        except requests.RequestException as exc:
            last_error = exc

    if last_error:
        raise last_error

    raise RuntimeError("Requests fetch failed without an explicit exception.")


def _parse_curl_header_blocks(raw_headers: str) -> tuple[requests.structures.CaseInsensitiveDict, list[str]]:
    """Parse the final HTTP header block and collect exposed Set-Cookie headers."""
    blocks = []
    current_block = []

    for line in raw_headers.splitlines():
        stripped = line.rstrip("\r")
        if stripped.startswith("HTTP/"):
            if current_block:
                blocks.append(current_block)
            current_block = [stripped]
            continue
        if current_block:
            if stripped:
                current_block.append(stripped)
            else:
                blocks.append(current_block)
                current_block = []

    if current_block:
        blocks.append(current_block)

    if not blocks:
        return requests.structures.CaseInsensitiveDict(), []

    final_block = blocks[-1]
    message = Parser().parsestr("\n".join(final_block[1:]))
    headers = requests.structures.CaseInsensitiveDict(dict(message.items()))
    if final_block and final_block[0].startswith("HTTP/"):
        headers["X-Audit-HTTP-Version"] = final_block[0].split(" ", 1)[0].upper()
    set_cookie_headers = message.get_all("Set-Cookie", []) or []
    return headers, set_cookie_headers


def _cookie_names_from_headers(set_cookie_headers: list[str]) -> list[str]:
    """Extract cookie names from raw Set-Cookie headers."""
    names = []
    for header in set_cookie_headers:
        cookie_name = header.split(";", 1)[0].split("=", 1)[0].strip()
        if cookie_name:
            names.append(cookie_name)
    return names


def _fetch_with_curl(
    url: str,
    timeout: int,
    verify,
) -> tuple[str, requests.structures.CaseInsensitiveDict, str, list[str], list[str]]:
    """Fetch a page with curl to benefit from a different TLS and HTTP stack."""
    curl_binary = shutil.which("curl")
    if not curl_binary:
        raise RuntimeError("curl is not available in this environment.")

    with tempfile.TemporaryDirectory(prefix="audit-fetch-") as temp_dir:
        temp_path = Path(temp_dir)
        header_path = temp_path / "headers.txt"
        body_path = temp_path / "body.html"

        command = [
            curl_binary,
            "--silent",
            "--show-error",
            "--location",
            "--compressed",
            "--max-time",
            str(timeout),
            "--cacert" if verify else "--insecure",
            TLS_CA_BUNDLE if verify else "",
            "--header",
            f"User-Agent: {DEFAULT_HEADERS['User-Agent']}",
            "--header",
            f"Accept: {DEFAULT_HEADERS['Accept']}",
            "--header",
            f"Accept-Language: {DEFAULT_HEADERS['Accept-Language']}",
            "--header",
            f"Cache-Control: {DEFAULT_HEADERS['Cache-Control']}",
            "--header",
            f"Pragma: {DEFAULT_HEADERS['Pragma']}",
            "--header",
            f"Upgrade-Insecure-Requests: {DEFAULT_HEADERS['Upgrade-Insecure-Requests']}",
            "--header",
            "Sec-Fetch-Dest: document",
            "--header",
            "Sec-Fetch-Mode: navigate",
            "--header",
            "Sec-Fetch-Site: none",
            "--header",
            "Sec-Fetch-User: ?1",
            "--dump-header",
            str(header_path),
            "--output",
            str(body_path),
            "--write-out",
            "%{url_effective}\n%{http_code}",
            url,
        ]
        if not verify:
            command = [part for part in command if part != ""]

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            raise RuntimeError(stderr or f"curl exited with code {completed.returncode}.")

        stdout_lines = (completed.stdout or "").splitlines()
        final_url = stdout_lines[0].strip() if stdout_lines else url
        http_code = stdout_lines[1].strip() if len(stdout_lines) > 1 else ""

        if http_code and not http_code.startswith(("2", "3")):
            raise RuntimeError(f"{http_code} response returned by curl for url: {final_url}")

        raw_headers = header_path.read_text(encoding="utf-8", errors="replace")
        headers, set_cookie_headers = _parse_curl_header_blocks(raw_headers)
        body = body_path.read_text(encoding="utf-8", errors="replace")
        cookie_names = _cookie_names_from_headers(set_cookie_headers)
        return body, headers, final_url, cookie_names, set_cookie_headers


def _is_certificate_verification_error(exc: Exception) -> bool:
    message = str(exc).lower()
    markers = (
        "certificate verify failed",
        "certificateverificationerror",
        "unable to get local issuer certificate",
        "self signed certificate",
    )
    return any(marker in message for marker in markers)


def _insecure_ssl_error_message(url: str) -> str:
    return (
        f"TLS certificate validation failed for {url}. "
        "The target could not be fetched even after secure and insecure retries."
    )


def probe_post_forms(base_url: str, pages: list[dict], max_forms: int = 2, timeout: int = 12) -> list[dict]:
    """Submit a very small number of low-risk same-origin POST forms for exposure review."""
    parsed_base = urlparse(base_url)
    domain_key = (parsed_base.hostname or "").lower().removeprefix("www.")
    findings = []
    attempted = 0
    session = requests.Session()
    skip_keywords = {
        "login", "signin", "sign-in", "password", "checkout", "payment", "delete",
        "remove", "logout", "admin", "register", "account", "cart", "upload", "comment",
    }
    field_types = {"text", "email", "search", "hidden", "tel"}

    for page in pages:
        if attempted >= max_forms:
            break

        soup = BeautifulSoup(page.get("html", "") or "", "html.parser")
        for form in soup.find_all("form"):
            if attempted >= max_forms:
                break

            method = (form.get("method") or "get").strip().lower()
            if method != "post":
                continue

            action = urljoin(page.get("final_url") or base_url, form.get("action") or page.get("final_url") or base_url)
            parsed_action = urlparse(action)
            action_host = (parsed_action.hostname or "").lower().removeprefix("www.")
            lowered_action = action.lower()
            if action_host and action_host != domain_key:
                continue
            if any(keyword in lowered_action for keyword in skip_keywords):
                continue

            inputs = form.find_all(["input", "select", "textarea"])
            payload = {}
            skip_form = False
            meaningful_fields = 0

            for field in inputs:
                name = (field.get("name") or "").strip()
                field_type = (field.get("type") or "text").strip().lower()
                if not name:
                    continue
                lowered_name = name.lower()
                if any(keyword in lowered_name for keyword in skip_keywords):
                    skip_form = True
                    break
                if field_type in {"password", "file", "submit", "reset", "button", "image"}:
                    skip_form = True
                    break

                if field.name == "textarea":
                    payload[name] = "audit probe message"
                    meaningful_fields += 1
                elif field.name == "select":
                    options = field.find_all("option")
                    if options:
                        payload[name] = options[0].get("value") or options[0].get_text(strip=True)
                        meaningful_fields += 1
                elif field_type in field_types:
                    payload[name] = (
                        "audit-probe@example.com" if field_type == "email" or "email" in lowered_name else "audit-probe"
                    )
                    meaningful_fields += 1
                elif field_type in {"checkbox", "radio"}:
                    if field.has_attr("checked") or field.get("value"):
                        payload[name] = field.get("value") or "1"
                else:
                    value = field.get("value")
                    if value is not None:
                        payload[name] = value

            if skip_form or meaningful_fields == 0 or meaningful_fields > 6:
                continue

            attempted += 1
            try:
                response = session.post(
                    action,
                    data=payload,
                    timeout=timeout,
                    headers={**DEFAULT_HEADERS, "Referer": page.get("final_url") or base_url},
                    allow_redirects=True,
                    verify=TLS_CA_BUNDLE,
                )
                response_text = response.text or ""
                reflected = "audit-probe" in response_text.lower()
                server_error = response.status_code >= 500
                findings.append(
                    {
                        "page_url": page.get("final_url") or page.get("url") or base_url,
                        "action": action,
                        "status_code": response.status_code,
                        "reflected_input": reflected,
                        "server_error": server_error,
                        "detail": (
                            "Probe input was reflected in the response body."
                            if reflected
                            else "Form accepted a low-risk POST probe without obvious input reflection."
                        ),
                    }
                )
            except requests.RequestException as exc:
                findings.append(
                    {
                        "page_url": page.get("final_url") or page.get("url") or base_url,
                        "action": action,
                        "status_code": "Request failed",
                        "reflected_input": False,
                        "server_error": False,
                        "detail": str(exc),
                    }
                )

    return findings


def fetch_text_asset(asset_url: str, timeout: int = 10, max_bytes: int = 300000) -> str:
    """Fetch a text-like asset body for version fingerprinting."""
    normalized_url = normalize_url(asset_url)
    response = requests.get(
        normalized_url,
        timeout=timeout,
        headers=DEFAULT_HEADERS,
        allow_redirects=True,
        verify=TLS_CA_BUNDLE,
    )
    response.raise_for_status()
    content_type = (response.headers.get("Content-Type") or "").lower()
    if not any(token in content_type for token in ("javascript", "css", "text", "json")) and content_type:
        return ""
    body = response.text or ""
    return body[:max_bytes]


def fetch_page(
    url: str,
    timeout: int = 15,
) -> tuple[str, requests.structures.CaseInsensitiveDict, str, list[str], list[str], str | None]:
    """Fetch a page, using curl as a fallback for bot-protected targets."""
    normalized_url = normalize_url(url)
    session = requests.Session()
    request_error: Exception | None = None

    try:
        body, headers, final_url, cookies, set_cookie_headers = _fetch_with_requests(
            session,
            normalized_url,
            timeout,
            verify=TLS_CA_BUNDLE,
        )
        return body, headers, final_url, cookies, set_cookie_headers, None
    except requests.HTTPError as exc:
        request_error = exc
        is_forbidden = exc.response is not None and exc.response.status_code == 403
        if not is_forbidden:
            raise RuntimeError(str(exc)) from exc
    except requests.RequestException as exc:
        request_error = exc

    try:
        body, headers, final_url, cookies, set_cookie_headers = _fetch_with_curl(
            normalized_url,
            timeout,
            verify=True,
        )
        return body, headers, final_url, cookies, set_cookie_headers, None
    except RuntimeError as curl_error:
        curl_error_message = str(curl_error)
        if "403" in str(curl_error):
            raise RuntimeError(
                f"403 Client Error: Forbidden for url: {normalized_url}. "
                "The target appears to block automated traffic even after a browser-like fallback. "
                "Try again from a residential IP or add a headless browser fetch path for this deployment."
            ) from curl_error
        if request_error is not None and _is_certificate_verification_error(request_error):
            warning = (
                "The site was fetched only after bypassing TLS certificate validation because its certificate "
                "chain could not be verified. Treat the result as best-effort and confirm the site's certificate "
                "configuration separately."
            )
            try:
                try:
                    body, headers, final_url, cookies, set_cookie_headers = _fetch_with_requests(
                        session,
                        normalized_url,
                        timeout,
                        verify=False,
                    )
                except requests.RequestException:
                    body, headers, final_url, cookies, set_cookie_headers = _fetch_with_curl(
                        normalized_url,
                        timeout,
                        verify=False,
                    )
                return body, headers, final_url, cookies, set_cookie_headers, warning
            except (requests.RequestException, RuntimeError) as insecure_error:
                raise RuntimeError(_insecure_ssl_error_message(normalized_url)) from insecure_error
        if request_error is not None:
            raise RuntimeError(
                f"{request_error}. The target could not be fetched with either the default HTTP client "
                "or the browser-like curl fallback."
            ) from curl_error
        raise RuntimeError(curl_error_message) from curl_error
