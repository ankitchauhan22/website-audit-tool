import re


def detect_drupal_modules(assets):
    modules = {}
    patterns = [
        r"/modules/([^/]+)/",
        r"/sites/all/modules/([^/]+)/",
        r"/core/modules/([^/]+)/",
    ]

    for asset in assets:
        for pattern in patterns:
            match = re.search(pattern, asset, flags=re.IGNORECASE)
            if match:
                name = match.group(1)
                modules[name] = {
                    "name": name,
                    "detected_version": "Not publicly exposed",
                    "recommended_version": "Current supported release",
                }

    return sorted(modules.values(), key=lambda module: module["name"].lower())
