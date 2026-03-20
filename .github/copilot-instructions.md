OBJECTIVE
--------------------------------

Build a lightweight Website Audit Tool that scans a website using SquirrelScan and displays the results on a single webpage.

The tool must allow a user to:
1. Enter a website URL in a textbox.
2. Run a security scan using the SquirrelScan CLI.
3. Display structured scan results detailed on the same webpage with information about the platform, modules or plugin as applicable, JavaScript libraries, security headers, Miscellaneous, Reverse proxies, Performance, Programming languages, Marketing automation,  database, infrastructure information, and Recommendation in the last.
4. Leverage AI if possible to find out information publicly.
5. Export the scan results as a downloadable PDF report.

The application must be secure, modular, and easy to run locally.

The final application should run locally and be accessible at:
http://localhost:5000

--------------------------------
ROLE & TECH STACK
--------------------------------

You are a senior software engineer and security tooling architect.

Build the tool using the following stack:

Backend
- Python 3.11+
- Flask web framework
- subprocess module for CLI execution
- JSON processing

Frontend
- HTML5
- Vanilla JavaScript
- CSS (minimal styling)
- Bootstrap 5 CSS using CDNJS

Reporting
- Python ReportLab library for PDF generation

Security Scanner
- SquirrelScan CLI from:
  https://github.com/squirrelscan/squirrelscan

--------------------------------
CORE DEVELOPMENT RULES
--------------------------------

Follow these strict development rules:

1. Use a clean modular architecture.
2. Separate backend, frontend, and scanner logic.
3. Validate all user input.
4. Never execute raw user input in shell commands.
5. Use safe subprocess execution.
6. Return structured JSON responses.
7. Implement proper error handling.
8. Prevent command injection attacks.
9. Sanitize all output before rendering in HTML.
10. Maintain readable and maintainable code.

--------------------------------
TECHNICAL REQUIREMENTS
--------------------------------

Backend requirements:

Create a Flask server with the following endpoints:

GET /
    Serve the main UI page.

POST /scan
    Accept JSON payload:

    {
        "url": "https://example.com"
    }

Processing flow:
- Validate URL format.
- Execute SquirrelScan via subprocess.
- Capture scanner output.
- Parse output into JSON.
- Return scan report to frontend.

Scanner command example:

    python3 squirrelscan.py <url> --json

POST /export-pdf

Input:
- Scan results JSON

Process:
- Generate a PDF audit report.
- Return the PDF as a downloadable file.

Error Handling:

- Timeout scans after 120 seconds.
- Return clear error messages.
- Log scanner failures safely.

--------------------------------
FRONTEND & ASSET MANAGEMENT
--------------------------------

Build a simple single-page interface.

UI components:

1. Website URL input textbox
2. "Scan Website" button
3. Scan progress indicator
4. Results display panel
5. "Export PDF" button

Frontend behavior:

- Send POST request to /scan using fetch API.
- Render returned JSON in a formatted report view.
- Allow exporting the report via /export-pdf endpoint.

Report sections should include:

- Target URL
- Security Headers
- Cookie Issues
- SSL Configuration
- Discovered Vulnerabilities

Styling rules:

- Use simple responsive CSS
- Ensure readable formatting
- Avoid heavy frameworks

--------------------------------
FORBIDDEN ACTIONS
--------------------------------

The generated code MUST NOT:

1. Execute unsanitized shell commands.
2. Allow arbitrary command execution.
3. Run SquirrelScan from the browser.
4. Expose server file paths.
5. Disable input validation.
6. Use unnecessary large frameworks (React, Angular, Vue).
7. Mix backend logic inside HTML templates.
8. Store user input without sanitization.
9. Ignore subprocess errors.

--------------------------------
DELIVERABLES
--------------------------------

Generate a complete working project with the following structure:

website-audit-tool
│
├── app.py
├── scanner.py
├── pdf_report.py
├── requirements.txt
│
├── templates
│   └── index.html
│
├── static
│   ├── script.js
│   └── style.css

Include:

1. Full code for each file
2. Python dependency list
3. Installation instructions
4. Run instructions
5. Example scan output

--------------------------------
RUN INSTRUCTIONS
--------------------------------

The project must run locally using:

    python app.py

The application should start at:

    http://localhost:5000

--------------------------------
OUTPUT FORMAT
--------------------------------

Return full working code for every file in the project with explanations where necessary.
# Website Audit Tool Contributor Notes

## Architecture

- Keep the scan orchestration in `scanner.py`.
- Put detection logic in `detectors/`.
- Put scoring, recommendations, and version guidance in `services/`.
- Keep Flask setup in `audit_tool/` and leave UI files in `templates/` and `static/`.

## Coding expectations

- Prefer small pure functions for detection and scoring logic.
- Keep the scan passive; do not add authenticated or intrusive checks by default.
- Return dictionaries and lists with stable keys so the template and PDF generator remain aligned.
- Validate URLs before making network requests and surface user-friendly errors.

## UI expectations

- Keep the interface simple and readable on desktop and mobile.
- Avoid inline styles in templates when the same rule belongs in `static/style.css`.
- Prefer evidence-based wording such as `No strong CMS fingerprint detected` or `Not publicly exposed` over generic `Unknown` labels.
- Treat WordPress and Drupal as the primary CMS focus.
- Show WordPress plugins only for WordPress sites.
- Show modules or extensions for Drupal and for other non-WordPress sites.
- Include a visible health-score breakdown so the score is explainable rather than opaque.
- For framework-based sites, surface as much passive evidence as possible from headers, cookies, assets, generator metadata, and stack signals.
- Favor grouped, client-readable sections such as reverse proxies, performance, programming languages, marketing automation, database clues, transport and SSL, cookie issues, and miscellaneous evidence.
- SquirrelScan is optional integration. The app must remain useful when it is missing or failing.
