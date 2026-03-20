const form = document.querySelector("[data-audit-form]");
const urlInput = document.querySelector("#url");
const statusBanner = document.querySelector("[data-status]");
const resultsSection = document.querySelector("[data-results]");
const exportButton = document.querySelector("[data-export-pdf]");
const submitButton = document.querySelector("[data-submit-button]");

let latestResult = null;

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function renderTable(headers, rows) {
    if (!rows.length) {
        return '<p class="muted">No data available for this section.</p>';
    }

    const head = headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("");
    const body = rows
        .map(
            (row) => `
                <tr>
                    ${row.map((cell) => `<td>${cell}</td>`).join("")}
                </tr>
            `
        )
        .join("");

    return `
        <div class="table-wrap">
            <table>
                <thead><tr>${head}</tr></thead>
                <tbody>${body}</tbody>
            </table>
        </div>
    `;
}

function renderLoadingState(url) {
    resultsSection.innerHTML = `
        <section class="card loader-card" aria-live="polite">
            <div class="loader-mark" aria-hidden="true">
                <span></span>
                <span></span>
                <span></span>
            </div>
            <div>
                <p class="eyebrow">Audit In Progress</p>
                <h2>Profiling ${escapeHtml(url)}</h2>
                <p class="muted">
                    Collecting headers, cookies, HTML markers, and public asset clues to build the audit report.
                </p>
            </div>
        </section>
    `;
}

function renderTechnologySections(sections) {
    if (!sections?.length) {
        return '<p class="muted">No structured technology profile was inferred from passive evidence.</p>';
    }

    return sections
        .map((section) => {
            const rows = section.items.map((item) => [
                escapeHtml(item.name),
                `<span class="status status-${String(item.status || "Observed").toLowerCase().replaceAll(" ", "-")}">${escapeHtml(item.status || "Observed")}</span>`,
                escapeHtml(item.confidence),
                escapeHtml(item.evidence),
                escapeHtml(item.status_reason || "No lifecycle assessment available."),
            ]);
            const sectionSummary = section.summary || "Review this section against your internal asset inventory.";

            return `
                <article class="card">
                    <div class="section-heading">
                        <h3>${escapeHtml(section.title)}</h3>
                        <span class="section-pill ${section.risk_count || section.review_count ? "section-pill-alert" : "section-pill-ok"}">${escapeHtml(sectionSummary)}</span>
                    </div>
                    <p class="muted">${escapeHtml(section.description)}</p>
                    ${renderTable(["Technology", "Lifecycle", "Confidence", "Evidence", "Why It Matters"], rows)}
                </article>
            `;
        })
        .join("");
}

function renderRecommendations(items) {
    if (!items?.length) {
        return '<p class="muted">No recommendations available.</p>';
    }

    return items.map((rawItem) => {
        const item = typeof rawItem === "string"
            ? { severity: "monitor", title: "Recommendation", action: rawItem, evidence: "" }
            : rawItem;
        return `
        <li class="recommendation-item recommendation-${escapeHtml(item.severity || "monitor")}">
            <div class="recommendation-head">
                <span class="recommendation-badge recommendation-badge-${escapeHtml(item.severity || "monitor")}">${escapeHtml((item.severity || "monitor").toUpperCase())}</span>
                <strong>${escapeHtml(item.title || "Recommendation")}</strong>
            </div>
            <div class="recommendation-body">
                <p>${escapeHtml(item.action || "")}</p>
                <small>${escapeHtml(item.evidence || "")}</small>
            </div>
        </li>
    `;
    }).join("");
}

function renderResult(result) {
    const pluginRows = (result.plugins || []).map((plugin) => [
        escapeHtml(plugin.name),
        escapeHtml(plugin.detected_version),
        escapeHtml(plugin.recommended_version),
    ]);
    const moduleRows = (result.modules || []).map((module) => [
        escapeHtml(module.name),
        escapeHtml(module.detected_version),
        escapeHtml(module.recommended_version),
    ]);
    const libraryRows = (result.libraries || []).map((library) => [
        escapeHtml(library.name),
        escapeHtml(library.detected_version),
        escapeHtml(library.recommended_version),
    ]);
    const stackRows = (result.technology_stack || []).map((item) => [
        escapeHtml(item.category),
        escapeHtml(item.name),
        `<span class="status status-${String(item.status || "Observed").toLowerCase().replaceAll(" ", "-")}">${escapeHtml(item.status || "Observed")}</span>`,
        escapeHtml(item.confidence),
        escapeHtml(item.evidence),
        escapeHtml(item.detected_version || "Not publicly exposed"),
        escapeHtml(item.recommended_track || "No structured release track"),
    ]);
    const securityRows = (result.security || []).map((item) => [
        escapeHtml(item.header),
        escapeHtml(item.parameter),
        escapeHtml(item.detected),
        `<span class="status ${String(item.status).toLowerCase()}">${escapeHtml(item.status)}</span>`,
    ]);
    const infraRows = (result.infra || []).map((item) => [
        escapeHtml(item.component),
        escapeHtml(item.detected),
        escapeHtml(item.recommended),
    ]);
    const cookieRows = (result.cookies || []).map((cookie) => [escapeHtml(cookie)]);
    const cookieIssueRows = (result.cookie_issues || []).map((item) => [
        escapeHtml(item.name),
        escapeHtml(item.issue),
    ]);
    const transportRows = (result.transport || []).map((item) => [
        escapeHtml(item.check),
        escapeHtml(item.value),
        escapeHtml(item.detail),
    ]);
    const scoreBreakdownRows = (result.score_breakdown || []).map((item) => [
        escapeHtml(item.label),
        `<span class="status status-${String(item.severity || "monitor").toLowerCase()}">${escapeHtml(item.severity || "monitor")}</span>`,
        escapeHtml(item.detail || ""),
        escapeHtml(item.action || ""),
        escapeHtml(item.impact > 0 ? `+${item.impact}` : item.impact),
    ]);
    const cmsMatches = Array.isArray(result.cms_matches) ? result.cms_matches : [];
    const warningBanner = result.fetch_warning
        ? `
            <section class="card notice-card notice-warning">
                <span class="notice-label">Fetch Warning</span>
                <p>${escapeHtml(result.fetch_warning)}</p>
            </section>
        `
        : "";
    const componentTitle = escapeHtml(result.component_label || "Modules / Extensions");
    const componentRows = result.cms === "WordPress" ? pluginRows : moduleRows;
    const componentIntro = result.cms === "WordPress"
        ? "Plugin fingerprints inferred from public WordPress asset paths."
        : "Module or extension fingerprints inferred from public asset paths.";
    const versionLabel = result.platform_name && result.platform_name !== result.cms
        ? `${escapeHtml(result.platform_name)} Version`
        : "Detected Version";
    const platformValue = result.cms === "No strong CMS fingerprint detected" && result.platform_name
        ? `${escapeHtml(result.platform_name)} <small class="inline-note">from passive stack evidence</small>`
        : escapeHtml(result.cms_summary || result.cms);
    const cmsMatchRows = cmsMatches.map((item) => [
        escapeHtml(item.name),
        escapeHtml(item.role || "Observed"),
        escapeHtml(item.family || "Unknown"),
        escapeHtml(item.confidence || "Observed"),
    ]);

    resultsSection.innerHTML = `
        ${warningBanner}
        <section class="summary-grid">
            <article class="card metric-card metric-card-platform">
                <span class="metric-label">${escapeHtml(result.platform_label || "Platform Assessment")}</span>
                <strong>${platformValue}</strong>
                <small>Recommended track: ${escapeHtml(result.recommended_cms_version)}</small>
            </article>
            <article class="card metric-card metric-card-version">
                <span class="metric-label">${versionLabel}</span>
                <strong>${escapeHtml(result.version)}</strong>
                <small>Recommended track: ${escapeHtml(result.recommended_cms_version)}</small>
            </article>
            <article class="card metric-card metric-card-score metric-card-score-${String(result.risk || "Medium").toLowerCase()}">
                <span class="metric-label">Health Score</span>
                <strong>${escapeHtml(result.score)}/100</strong>
                <small>${escapeHtml(result.audit_method || "Passive profile")} · Risk: ${escapeHtml(result.risk)}</small>
            </article>
        </section>

        <section class="card mt-3">
            <h2>Health Score Breakdown</h2>
            <p class="muted">
                This summary explains what most affected the score, why it matters operationally, and what should be
                fixed first so stakeholders can move from passive evidence to remediation.
            </p>
            ${renderTable(["Factor", "Priority", "Why It Matters", "Recommended Action", "Impact"], scoreBreakdownRows)}
        </section>

        <section class="card mt-3">
            <div class="section-header">
                <h2>Recommendations</h2>
                <button type="button" class="secondary-button" data-export-pdf>Export PDF</button>
            </div>
            <ul class="recommendations rich-recommendations">
                ${renderRecommendations(result.recommendations || [])}
            </ul>
        </section>

        <section class="data-grid">
            <article class="card">
                <h2>${componentTitle}</h2>
                <p class="muted">
                    ${componentIntro} These findings indicate public-facing software surface area that may affect
                    patching effort, maintenance overhead, and upgrade planning.
                </p>
                <h3>${componentTitle}</h3>
                ${renderTable(["Name", "Detected Version", "Recommended"], componentRows)}
                <h3>Libraries</h3>
                ${renderTable(["Name", "Detected Version", "Recommended"], libraryRows)}
            </article>

            <article class="card">
                <h2>CMS Detection</h2>
                <p class="muted">
                    Primary and secondary CMS findings are ranked from passive evidence only. Headless and proprietary
                    platforms are shown when public signals are strong enough to support a precise classification.
                </p>
                ${renderTable(["Platform", "Role", "Family", "Confidence"], cmsMatchRows)}
                <h3 class="mt-3">Security Headers and Infrastructure</h3>
                <p class="muted">
                    These settings influence browser trust, clickjacking protection, content handling, and how the
                    site is delivered through its visible infrastructure.
                </p>
                ${renderTable(["Header", "Purpose", "Detected", "Status"], securityRows)}
                <h3 class="mt-3">Infrastructure</h3>
                ${renderTable(["Component", "Detected", "Recommended"], infraRows)}
            </article>
        </section>

        <section class="data-grid">
            <article class="card">
                <h2>Transport and Cookie Signals</h2>
                <p class="muted">
                    This section highlights controls that affect secure delivery, session protection, and how browsers
                    cache or trust the experience.
                </p>
                ${renderTable(["Check", "Value", "Detail"], transportRows)}
                <h3>Observed Cookies</h3>
                ${renderTable(["Cookie Name"], cookieRows)}
                <h3>Cookie Issues</h3>
                ${renderTable(["Cookie", "Observed Issue"], cookieIssueRows)}
            </article>

            <article class="card">
                <h2>Miscellaneous</h2>
                <p class="muted">
                    These supporting signals help explain what the site exposes publicly and whether it reveals helpful
                    operational metadata to third parties.
                </p>
                <p><strong>Meta generator:</strong> ${escapeHtml(result.meta_generator || "Not exposed")}</p>
                <p><strong>Requested URL:</strong> ${escapeHtml(result.url)}</p>
                <p><strong>Resolved URL:</strong> ${escapeHtml(result.final_url)}</p>
            </article>
        </section>

        <section class="technology-grid">
            ${renderTechnologySections(result.technology_profile)}
        </section>

        <section class="card mt-3">
            <h2>All Technology Signals</h2>
            <p class="muted">
                This appendix lists every passive signal collected from public HTML, headers, asset paths, and cookie
                names so technical teams can validate the evidence behind the customer-facing summary above.
            </p>
            ${renderTable(["Category", "Technology", "Lifecycle", "Confidence", "Evidence", "Observed Version", "Recommended Track"], stackRows)}
        </section>
    `;

    latestResult = result;
    exportButton.hidden = true;
    const inlineExportButton = resultsSection.querySelector("[data-export-pdf]");
    inlineExportButton?.addEventListener("click", exportPdf);
}

function setStatus(message, type = "info") {
    statusBanner.textContent = message;
    statusBanner.dataset.state = type;
    statusBanner.hidden = !message;
}

function setBusyState(isBusy) {
    submitButton.disabled = isBusy;
    submitButton.textContent = isBusy ? "Auditing..." : "Audit Website";
    form?.toggleAttribute("aria-busy", isBusy);
}

async function runAudit(event) {
    event.preventDefault();
    const url = urlInput.value.trim();
    if (!url) {
        setStatus("Enter a website URL to run the audit.", "error");
        return;
    }

    setBusyState(true);
    setStatus("Running passive audit and technology profiling...", "loading");
    renderLoadingState(url);
    latestResult = null;

    try {
        const response = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });
        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || "The audit could not be completed.");
        }

        renderResult(result);
        setStatus("Audit completed successfully.", "success");
    } catch (error) {
        resultsSection.innerHTML = "";
        setStatus(error.message || "The audit could not be completed.", "error");
    } finally {
        setBusyState(false);
    }
}

async function exportPdf() {
    if (!latestResult) {
        setStatus("Run an audit before exporting a PDF.", "error");
        return;
    }

    setStatus("Generating PDF report...", "loading");

    try {
        const response = await fetch("/export-pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(latestResult),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || "PDF export failed.");
        }

        const blob = await response.blob();
        const blobUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = blobUrl;
        link.download = "website-audit-report.pdf";
        link.click();
        URL.revokeObjectURL(blobUrl);
        setStatus("PDF report downloaded.", "success");
    } catch (error) {
        setStatus(error.message || "PDF export failed.", "error");
    }
}

form?.addEventListener("submit", runAudit);
exportButton?.addEventListener("click", exportPdf);
