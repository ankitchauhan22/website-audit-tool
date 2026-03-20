# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added
- Expanded CMS detection for proprietary, headless, enterprise, and government platforms including Sitefinity, SharePoint, CivicPlus Web Central, CivicPlus HCMS, CivicLive, ProdCity, TerminalFour, ButterCMS, Craft CMS, Granicus govAccess, and OpenCities.
- Added broader framework and runtime detection including Remix, Alpine.js, Ember.js, Preact, CakePHP, and Zend Framework.
- Added ranked CMS output with primary and secondary platform reporting plus confidence levels.
- Added richer recommendation objects with severity, action, and evidence fields.
- Added GitHub Actions validation workflow and PR merge release-comment workflow.
- Added `.gitignore`, `pyproject.toml`, and this changelog.

### Changed
- Improved WordPress detection so public `wp-*` evidence can promote WordPress to the primary CMS result.
- Switched WordPress recommended release tracking to the official WordPress core update API instead of relying on stale hardcoded values.
- Tightened WordPress version parsing to ignore non-semantic cache-busting query strings.
- Expanded plugin and module detection to inspect full page HTML, request-visible asset URLs, and headers instead of only simple asset lists.
- Reworked recommendation rendering with risk-coded cards and more actionable remediation language.
- Improved health score breakdown output to explain impact, urgency, and the next remediation step.
- Reworked PDF export structure into a clearer executive-summary-first audit report.
- Improved UI branding, score cards, warning states, and recommendation layout.
- Updated Vercel deployment guidance and aligned Python version metadata for deployment stability.

### Fixed
- Reduced TLS certificate validation failures by using the `certifi` CA bundle for both `requests` and curl-based fetch paths.
- Added a last-resort automatic insecure TLS retry with visible scan warnings when certificate chains are broken.
- Fixed summary card fallback behavior so the inferred primary platform is shown instead of an unrelated first stack signal.
- Fixed customer-facing wording for cases where public version evidence is unavailable by explaining which passive checks were already attempted.

### Removed
- Removed the empty `static/` directory.
