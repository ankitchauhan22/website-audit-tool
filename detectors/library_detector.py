import re


LIBRARY_RULES = [
    ("jQuery", re.compile(r"jquery[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), "3.7.1"),
    ("Bootstrap", re.compile(r"bootstrap[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), "5.x"),
    ("React", re.compile(r"react(?:[-.](\d+\.\d+(?:\.\d+)?))?", re.IGNORECASE), "19.2"),
    ("Vue.js", re.compile(r"vue(?:[-.](\d+\.\d+(?:\.\d+)?))?", re.IGNORECASE), "3.5.x"),
    ("Angular", re.compile(r"angular(?:[-.](\d+\.\d+(?:\.\d+)?))?", re.IGNORECASE), "21.x"),
    ("Astro", re.compile(r"astro(?:[-.](\d+\.\d+(?:\.\d+)?))?", re.IGNORECASE), "5.5.x"),
    ("Gatsby", re.compile(r"gatsby(?:[-.](\d+\.\d+(?:\.\d+)?))?", re.IGNORECASE), "5.16.x"),
]


def detect_libraries(assets):
    libraries = {}

    for asset in assets:
        for library_name, pattern, recommended_version in LIBRARY_RULES:
            if library_name.lower() not in asset.lower():
                continue

            match = pattern.search(asset)
            version = match.group(1) if match and match.lastindex else "Not publicly exposed"
            libraries[library_name] = {
                "name": library_name,
                "detected_version": version,
                "recommended_version": recommended_version,
            }

    return sorted(libraries.values(), key=lambda library: library["name"].lower())
