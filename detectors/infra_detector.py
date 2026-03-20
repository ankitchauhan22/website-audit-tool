def detect_infrastructure(headers):
    infra = []
    server = headers.get("Server", "Header not exposed")
    infra.append({
        "component": "Web Server",
        "detected": server,
        "recommended": "Latest stable"
    })

    if "cloudflare" in headers.get("Server","").lower():
        infra.append({
            "component": "CDN",
            "detected": "Cloudflare",
            "recommended": "Configured"
        })

    powered_by = headers.get("X-Powered-By")
    if powered_by:
        infra.append({
            "component": "Application Runtime",
            "detected": powered_by,
            "recommended": "Hide or harden if not needed"
        })

    via = headers.get("Via")
    if via:
        infra.append({
            "component": "Proxy Chain",
            "detected": via,
            "recommended": "Review upstream proxy exposure"
        })

    cache = headers.get("X-Cache") or headers.get("CF-Cache-Status")
    if cache:
        infra.append({
            "component": "Caching Layer",
            "detected": cache,
            "recommended": "Validate cache and purge strategy"
        })

    return infra
