import re


def _clean_evidence(value: str) -> str:
    """Turn a raw regex match into a compact, presentation-friendly evidence string."""
    cleaned = " ".join((value or "").split()).strip(" \"'")
    if len(cleaned) > 60:
        return f"{cleaned[:57]}..."
    return cleaned


STACK_PATTERNS = [
    {
        "category": "CMS",
        "name": "WordPress",
        "patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "confidence": "High",
    },
    {
        "category": "CMS",
        "name": "Drupal",
        "patterns": [r"/sites/default/", r"drupalsettings", r"/misc/drupal\.js"],
        "confidence": "High",
    },
    {
        "category": "CMS",
        "name": "Joomla",
        "patterns": [r"/media/system/js", r"joomla!", r"/templates/system/"],
        "confidence": "High",
    },
    {
        "category": "CMS",
        "name": "TYPO3",
        "patterns": [r"typo3conf", r"typo3temp", r"typo3"],
        "confidence": "High",
    },
    {
        "category": "CMS",
        "name": "Ghost",
        "patterns": [r"ghost-sdk", r"/ghost/api/", r"ghost-content"],
        "confidence": "High",
    },
    {
        "category": "CMS",
        "name": "Sitefinity",
        "patterns": [r"x-sf-service-request", r"/api/default/", r"telerik\.sitefinity", r"/restapi/markup"],
        "confidence": "High",
    },
    {
        "category": "CMS",
        "name": "SharePoint",
        "patterns": [r"/_layouts/15/", r"/_vti_bin/", r"sharepoint"],
        "confidence": "High",
    },
    {
        "category": "CMS",
        "name": "CivicPlus Web Central",
        "patterns": [r"/alertcenter/", r"/documentcenter/", r"/formcenter/", r"/facilities/", r"/calendar\.aspx", r"/civicalerts\.aspx"],
        "confidence": "High",
    },
    {
        "category": "CMS",
        "name": "CivicPlus HCMS",
        "patterns": [r"content\.civicplus\.com", r"api/content/", r"api/assets/"],
        "confidence": "High",
    },
    {
        "category": "CMS",
        "name": "ButterCMS",
        "patterns": [r"api\.buttercms\.com", r"buttercms"],
        "confidence": "Medium",
    },
    {
        "category": "CMS",
        "name": "CivicLive",
        "patterns": [r"powered by civiclive", r"civiclive\.com", r"civiclive"],
        "confidence": "Medium",
    },
    {
        "category": "CMS",
        "name": "ProdCity",
        "patterns": [r"powered by prodcity", r"prod\.city", r"prodcity"],
        "confidence": "Medium",
    },
    {
        "category": "CMS",
        "name": "TerminalFour",
        "patterns": [r"powered by terminalfour", r"terminalfour", r"terminal four"],
        "confidence": "Medium",
    },
    {
        "category": "CMS",
        "name": "Craft CMS",
        "patterns": [r"craft cms", r"/cpresources/", r"craftcms"],
        "confidence": "High",
    },
    {
        "category": "CMS",
        "name": "Granicus govAccess",
        "patterns": [r"govaccess", r"visioninternet"],
        "confidence": "Medium",
    },
    {
        "category": "CMS",
        "name": "OpenCities",
        "patterns": [r"opencities"],
        "confidence": "Medium",
    },
    {
        "category": "Commerce",
        "name": "Shopify",
        "patterns": [r"cdn\.shopify\.com", r"shopify\.theme", r"shopify-checkout-api-token"],
        "confidence": "High",
    },
    {
        "category": "Commerce",
        "name": "Magento",
        "patterns": [r"/static/frontend/", r"mage/cookies", r"magento"],
        "confidence": "High",
    },
    {
        "category": "Hosting",
        "name": "Wix",
        "patterns": [r"wixstatic\.com", r"_wixcss", r"wix-code-sdk"],
        "confidence": "High",
    },
    {
        "category": "Hosting",
        "name": "Squarespace",
        "patterns": [r"static\.squarespace\.com", r"squarespace-cdn", r"squarespace"],
        "confidence": "High",
    },
    {
        "category": "Hosting",
        "name": "Webflow",
        "patterns": [r"webflow\.js", r"webflow\.io", r"w-webflow-"],
        "confidence": "High",
    },
    {
        "category": "Analytics",
        "name": "Google Analytics",
        "patterns": [r"google-analytics\.com", r"gtag\(", r"G-[A-Z0-9]+"],
        "confidence": "High",
    },
    {
        "category": "Tag Manager",
        "name": "Google Tag Manager",
        "patterns": [r"googletagmanager\.com", r"GTM-[A-Z0-9]+"],
        "confidence": "High",
    },
    {
        "category": "Analytics",
        "name": "Hotjar",
        "patterns": [r"static\.hotjar\.com", r"hotjar"],
        "confidence": "High",
    },
    {
        "category": "Marketing",
        "name": "Meta Pixel",
        "patterns": [r"connect\.facebook\.net", r"fbq\("],
        "confidence": "High",
    },
    {
        "category": "Performance",
        "name": "Cloudflare",
        "patterns": [r"cloudflare", r"cf-ray", r"__cf_bm"],
        "confidence": "High",
    },
    {
        "category": "Proxy",
        "name": "Fastly",
        "patterns": [r"x-served-by:\s*cache-", r"fastly", r"x-cache-hits"],
        "confidence": "Medium",
    },
    {
        "category": "CDN",
        "name": "Akamai",
        "patterns": [r"akamai", r"akamaized\.net", r"ak_bmsc"],
        "confidence": "Medium",
    },
    {
        "category": "Hosting",
        "name": "Amazon Web Services",
        "patterns": [r"amazonaws\.com", r"x-amz-", r"awselb"],
        "confidence": "Medium",
    },
    {
        "category": "Hosting",
        "name": "Microsoft Azure",
        "patterns": [r"azure", r"azureedge\.net", r"x-azure-"],
        "confidence": "Medium",
    },
    {
        "category": "Runtime",
        "name": "PHP",
        "patterns": [r"x-powered-by:\s*php", r"phpsessid"],
        "confidence": "High",
    },
    {
        "category": "Runtime",
        "name": "ASP.NET",
        "patterns": [r"x-powered-by:\s*asp\.net", r"asp\.net", r"__viewstate"],
        "confidence": "High",
    },
    {
        "category": "Runtime",
        "name": "Node.js",
        "patterns": [r"x-powered-by:\s*express", r"__next", r"node\.js"],
        "confidence": "Medium",
    },
    {
        "category": "Runtime",
        "name": "Laravel",
        "patterns": [r"laravel_session", r"x-powered-by:\s*php", r"csrf-token"],
        "confidence": "Medium",
    },
    {
        "category": "Runtime",
        "name": "CakePHP",
        "patterns": [r"cakephp", r"cakephp:?", r"/js/cakephp", r"csrfToken"],
        "confidence": "Medium",
    },
    {
        "category": "Runtime",
        "name": "Zend Framework",
        "patterns": [r"zend framework", r"zendframework", r"zend-http", r"zend-session", r"zend_form"],
        "confidence": "Medium",
    },
    {
        "category": "Frontend",
        "name": "Vue.js",
        "patterns": [r"vue(?:\.runtime)?(?:\.min)?\.js", r"data-v-"],
        "confidence": "Medium",
    },
    {
        "category": "Frontend",
        "name": "Angular",
        "patterns": [r"ng-version=", r"_ngcontent-", r"ng-server-context"],
        "confidence": "Medium",
    },
    {
        "category": "Frontend",
        "name": "AngularJS",
        "patterns": [r"angular(?:\.min)?\.js", r"ng-app", r"ng-controller"],
        "confidence": "High",
    },
    {
        "category": "Frontend",
        "name": "Next.js",
        "patterns": [r"_next/static", r"__next"],
        "confidence": "High",
    },
    {
        "category": "Frontend",
        "name": "Nuxt",
        "patterns": [r"_nuxt/", r"__nuxt"],
        "confidence": "High",
    },
    {
        "category": "Frontend",
        "name": "Remix",
        "patterns": [r"__remixcontext", r"/build/_assets/", r"@remix-run"],
        "confidence": "High",
    },
    {
        "category": "Frontend",
        "name": "React",
        "patterns": [r"react(?:\.production)?(?:\.min)?\.js", r"data-reactroot", r"__react"],
        "confidence": "Medium",
    },
    {
        "category": "Frontend",
        "name": "Astro",
        "patterns": [r"_astro/", r"astro-island", r"astro/client"],
        "confidence": "High",
    },
    {
        "category": "Frontend",
        "name": "Gatsby",
        "patterns": [r"___gatsby", r"gatsby-script", r"gatsby-browser"],
        "confidence": "High",
    },
    {
        "category": "Frontend",
        "name": "Docusaurus",
        "patterns": [r"__docusaurus", r"docusaurus", r"infima"],
        "confidence": "High",
    },
    {
        "category": "Frontend",
        "name": "Svelte",
        "patterns": [r"svelte(?:@|[-.])", r"data-svelte-h", r"svelte-"],
        "confidence": "Medium",
    },
    {
        "category": "Frontend",
        "name": "SvelteKit",
        "patterns": [r"_app/immutable", r"data-sveltekit", r"@sveltejs/kit"],
        "confidence": "High",
    },
    {
        "category": "Frontend",
        "name": "Sapper",
        "patterns": [r"__sapper__", r"sapper"],
        "confidence": "High",
    },
    {
        "category": "Frontend",
        "name": "Alpine.js",
        "patterns": [r"x-data=", r"x-cloak", r"alpinejs"],
        "confidence": "Medium",
    },
    {
        "category": "Frontend",
        "name": "Ember.js",
        "patterns": [r"ember(?:\.min)?\.js", r"data-ember-action", r"ember-view"],
        "confidence": "Medium",
    },
    {
        "category": "Frontend",
        "name": "Preact",
        "patterns": [r"preact(?:\.min)?\.js", r"__preactattr_"],
        "confidence": "Medium",
    },
    {
        "category": "JavaScript Library",
        "name": "jQuery",
        "patterns": [r"jquery(?:[-.]\d+(?:\.\d+)*)?(?:\.min)?\.js", r"jquery-migrate"],
        "confidence": "High",
    },
    {
        "category": "JavaScript Library",
        "name": "Bootstrap",
        "patterns": [r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)", r"class=\"[^\"]*\bcontainer(?:-fluid)?\b"],
        "confidence": "Medium",
    },
    {
        "category": "JavaScript Library",
        "name": "jQuery UI",
        "patterns": [r"jquery-ui(?:\.min)?\.(?:js|css)", r"ui-datepicker", r"ui-widget"],
        "confidence": "High",
    },
    {
        "category": "JavaScript Library",
        "name": "Swiper",
        "patterns": [r"swiper(?:-bundle)?(?:\.min)?\.(?:js|css)", r"\bswiper-wrapper\b", r"\bswiper-slide\b"],
        "confidence": "High",
    },
    {
        "category": "Performance",
        "name": "LazySizes",
        "patterns": [r"lazysizes(?:\.min)?\.js", r"lazyload", r"data-src"],
        "confidence": "Medium",
    },
    {
        "category": "JavaScript Library",
        "name": "core-js",
        "patterns": [r"core-js(?:[-.]\d+(?:\.\d+)*)?", r"core-js/modules/"],
        "confidence": "Medium",
    },
    {
        "category": "JavaScript Library",
        "name": "AOS",
        "patterns": [r"(?:^|/)aos(?:\.min)?\.(?:js|css)", r"data-aos="],
        "confidence": "Medium",
    },
    {
        "category": "Consent",
        "name": "CookieYes",
        "patterns": [r"cookieyes", r"cookie-law-info", r"cky-consent"],
        "confidence": "High",
    },
    {
        "category": "Consent",
        "name": "OneTrust",
        "patterns": [r"onetrust", r"optanon"],
        "confidence": "High",
    },
    {
        "category": "Customer Support",
        "name": "Zendesk",
        "patterns": [r"zdassets\.com", r"zendesk"],
        "confidence": "Medium",
    },
    {
        "category": "Customer Support",
        "name": "Intercom",
        "patterns": [r"intercom", r"widget\.intercom\.io"],
        "confidence": "Medium",
    },
    {
        "category": "Security",
        "name": "reCAPTCHA",
        "patterns": [r"google\.com/recaptcha", r"g-recaptcha"],
        "confidence": "High",
    },
    {
        "category": "Security",
        "name": "Cloudflare Bot Management",
        "patterns": [r"__cf_bm", r"cf_clearance"],
        "confidence": "High",
    },
    {
        "category": "Database",
        "name": "MySQL",
        "patterns": [r"mysql", r"mariadb"],
        "confidence": "Low",
    },
    {
        "category": "Database",
        "name": "PostgreSQL",
        "patterns": [r"postgres", r"postgresql"],
        "confidence": "Low",
    },
    {
        "category": "Database",
        "name": "Redis",
        "patterns": [r"redis"],
        "confidence": "Low",
    },
]


def detect_stack_signals(html: str, headers, assets, cookies, meta_generator: str):
    """Infer technologies from public response data using passive signatures."""
    combined_parts = [html or "", meta_generator or ""]
    combined_parts.extend(assets or [])
    combined_parts.extend(f"{key}:{value}" for key, value in (headers or {}).items())
    combined_parts.extend(f"cookie:{cookie}" for cookie in (cookies or []))
    combined = "\n".join(combined_parts).lower()

    detections = {}
    for rule in STACK_PATTERNS:
        matches = []
        for pattern in rule["patterns"]:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                evidence = _clean_evidence(match.group(0))
                if evidence:
                    matches.append(evidence)

        if matches:
            detections[rule["name"]] = {
                "category": rule["category"],
                "name": rule["name"],
                "confidence": rule["confidence"],
                "evidence": ", ".join(dict.fromkeys(matches[:3])),
            }

    return sorted(
        detections.values(),
        key=lambda item: (item["category"].lower(), item["name"].lower()),
    )
