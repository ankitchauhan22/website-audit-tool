const form = document.querySelector("[data-audit-form]");
const urlInput = document.querySelector("#url");
const deepScanInput = document.querySelector("#deep-scan");
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
        .map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`)
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

function renderEmptyState(title, detail) {
    return `
        <div class="empty-state">
            <strong>${escapeHtml(title)}</strong>
            <p>${escapeHtml(detail)}</p>
        </div>
    `;
}

function renderLoadingState(url, deepScanEnabled) {
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
                    ${deepScanEnabled
                        ? "Reviewing headers, source exposure, and non-identical same-domain pages for a deeper passive audit."
                        : "Reviewing the requested page for platform, security, performance, and SEO signals."}
                </p>
            </div>
        </section>
    `;
}

function renderRecommendations(items) {
    if (!items?.length) {
        return '<p class="muted">No major remediation item was generated from this scan.</p>';
    }

    const priorityMap = { must: "P1", high: "P2", monitor: "P3" };
    return items.map((item) => `
        <li class="recommendation-item recommendation-${escapeHtml(item.severity || "high")}">
            <div class="recommendation-head">
                <span class="recommendation-badge recommendation-badge-${escapeHtml(item.severity || "high")}">${escapeHtml(priorityMap[item.severity || "high"] || "P2")}</span>
                <strong>${escapeHtml(item.title || "Recommendation")}</strong>
            </div>
            <div class="recommendation-body">
                <p>${escapeHtml(item.action || "")}</p>
                <small>${escapeHtml(item.evidence || "")}</small>
            </div>
        </li>
    `).join("");
}

function statusPill(value, tone) {
    return `<span class="status status-${escapeHtml(tone)}">${escapeHtml(value)}</span>`;
}

function scoreTone(score) {
    if (typeof score !== "number") {
        return "info";
    }
    if (score >= 90) {
        return "good";
    }
    if (score >= 60) {
        return "monitor";
    }
    return "high";
}

function clampScore(score) {
    return typeof score === "number" ? Math.max(0, Math.min(score, 100)) : null;
}

function scoreColor(score) {
    const clamped = clampScore(score);
    if (clamped == null) {
        return "#94a3b8";
    }
    if (clamped >= 90) {
        return "#16A34A";
    }
    if (clamped >= 75) {
        return "#FACC15";
    }
    if (clamped >= 60) {
        return "#F97316";
    }
    if (clamped >= 40) {
        return "#EF4444";
    }
    return "#7F1D1D";
}

function scoreSoftColor(score) {
    const clamped = clampScore(score);
    if (clamped == null) {
        return "#cbd5e1";
    }
    if (clamped >= 90) {
        return "#86EFAC";
    }
    if (clamped >= 75) {
        return "#FEF08A";
    }
    if (clamped >= 60) {
        return "#FDBA74";
    }
    if (clamped >= 40) {
        return "#FCA5A5";
    }
    return "#B91C1C";
}

function renderScoreMeter(score, label = "") {
    const clamped = clampScore(score);
    const width = clamped != null ? Math.max(8, clamped) : 16;
    const fillColor = scoreColor(score);
    const softColor = scoreSoftColor(score);
    return `
        <div class="score-meter">
            ${label ? `<div class="score-meter-label">${escapeHtml(label)}</div>` : ""}
            <div class="score-bar">
                <span class="score-bar-fill" style="width:${width}%; background: linear-gradient(90deg, ${fillColor}, ${softColor});"></span>
            </div>
        </div>
    `;
}

function renderPerformanceBreakdown(profileName, audit) {
    const factors = Array.isArray(audit?.benchmark_breakdown) ? audit.benchmark_breakdown : [];
    if (!factors.length) {
        return renderEmptyState(
            `No ${profileName} benchmark detail captured`,
            "This performance profile did not return enough metric detail to explain the benchmark scoring."
        );
    }

    const rows = factors.map((item) => [
        escapeHtml(item.name || "Factor"),
        escapeHtml(item.observed || "Not available"),
        escapeHtml(item.benchmark || "Not captured"),
        escapeHtml(`${item.achieved ?? 0}/${item.points ?? 0}`),
    ]);

    return renderTable(["Factor", "Observed", "Benchmark", "Points"], rows);
}

function renderTechnologySections(sections) {
    if (!sections?.length) {
        return renderEmptyState(
            "No grouped technology categories available",
            "The scan did not collect enough public evidence to group technology signals into audit categories."
        );
    }

    return `
        <div class="technology-grid">
            ${sections.map((section) => {
                const items = section.items || [];
                const rows = items.map((item) => [
                    escapeHtml(item.name),
                    statusPill(item.status || "Observed", String(item.status || "Observed").toLowerCase().replaceAll(" ", "-")),
                    escapeHtml(item.detected_version || "Not publicly exposed"),
                    escapeHtml(item.evidence || "Not captured"),
                ]);
                return `
                    <article class="card category-card">
                        <div class="category-card-head">
                            <div>
                                <h3>${escapeHtml(section.title)}</h3>
                                <p class="muted">${escapeHtml(section.description || "")}</p>
                            </div>
                            <span class="section-pill ${(section.risk_count || section.review_count) ? "section-pill-alert" : "section-pill-ok"}">
                                ${escapeHtml(section.summary || "Category summary not captured")}
                            </span>
                        </div>
                        ${renderTable(["Technology", "Lifecycle", "Version", "Evidence"], rows)}
                    </article>
                `;
            }).join("")}
        </div>
    `;
}

function signalTone(value) {
    const normalized = String(value || "").toLowerCase();
    if (["enabled", "aligned", "matches hostname", "present", "valid", "healthy"].includes(normalized)) {
        return "good";
    }
    if (normalized.includes("warning") || normalized.includes("review") || normalized.includes("expiring")) {
        return "monitor";
    }
    if (normalized.includes("failed") || normalized.includes("missing") || normalized.includes("not enabled") || normalized.includes("expired")) {
        return "high";
    }
    return "info";
}

function renderResult(result) {
    const performance = result.performance_audit || {};
    const seo = result.seo_audit || {};
    const markupValidation = seo.markup_validation || {};
    const scoreModel = result.score_model || {};
    const categoryScores = result.category_scores || {};
    const crawlSummary = result.crawl_summary || {};
    const websiteDetails = result.website_details || {};
    const cmsMatches = Array.isArray(result.cms_matches) ? result.cms_matches : [];
    const pagesScanned = crawlSummary.pages_scanned ?? 1;
    const componentRows = (result.cms === "WordPress" ? result.plugins : result.modules || [])
        .slice(0, 12)
        .map((item) => [
            escapeHtml(item.name),
            escapeHtml(item.detected_version),
            escapeHtml(item.recommended_version),
        ]);
    const libraryRows = (result.libraries || []).slice(0, 12).map((item) => [
        escapeHtml(item.name),
        escapeHtml(item.detected_version),
        escapeHtml(item.recommended_version),
        escapeHtml(item.cve_summary || "No CVE summary"),
    ]);
    const cmsRows = cmsMatches.map((item) => [
        escapeHtml(item.name),
        escapeHtml(item.role || "Observed"),
        escapeHtml(item.family || "Unknown"),
        escapeHtml(item.confidence || "Observed"),
    ]);
    const performanceRows = ["mobile", "desktop"].map((strategy) => {
        const audit = performance[strategy] || {};
        const score = audit.benchmark_score ?? audit.score;
        const tone = scoreTone(score);
        return [
            escapeHtml(strategy[0].toUpperCase() + strategy.slice(1)),
            statusPill(score != null ? `${score}/100` : "N/A", tone),
            escapeHtml(audit.largest_contentful_paint || "Not available"),
            escapeHtml(audit.first_contentful_paint || "Not available"),
            escapeHtml(audit.time_to_first_byte || "Not available"),
            escapeHtml(audit.interactive || "Not available"),
            escapeHtml((audit.recommendations || []).join(", ") || "No major opportunity captured"),
        ];
    });
    const performanceCards = ["mobile", "desktop"].map((strategy) => {
        const audit = performance[strategy] || {};
        const score = audit.benchmark_score ?? audit.score;
        const tone = scoreTone(score);
        const rawScore = audit.score;
        return `
            <article class="card perf-card perf-card-${tone}" style="--score-accent:${scoreColor(score)}; --score-accent-soft:${scoreSoftColor(score)};">
                <span class="metric-label">${escapeHtml(strategy[0].toUpperCase() + strategy.slice(1))} Score</span>
                <strong>${escapeHtml(score != null ? `${score}/100` : "N/A")}</strong>
                ${renderScoreMeter(score)}
                <small>${escapeHtml((audit.source || "Performance source") + (audit.estimated ? " (estimated)" : ""))}${rawScore != null ? ` · PSI headline: ${escapeHtml(`${rawScore}/100`)}` : ""}</small>
            </article>
        `;
    }).join("");
    const scoreBreakdownRows = (result.score_breakdown || [])
        .filter((item) => Number(item.impact) !== 0)
        .map((item) => [
            escapeHtml(item.label),
            statusPill(item.priority || "P3", String(item.severity || "monitor").toLowerCase()),
            escapeHtml(item.detail || ""),
            escapeHtml(item.action || ""),
            escapeHtml(item.impact),
        ]);
    const securityRows = (result.security || []).map((item) => [
        escapeHtml(item.header),
        escapeHtml(item.parameter),
        escapeHtml(item.detected),
        statusPill(item.status, String(item.status || "").toLowerCase()),
    ]);
    const transportRows = (result.transport || []).map((item) => [
        escapeHtml(item.check),
        statusPill(item.value, signalTone(item.value)),
        escapeHtml(item.detail),
    ]);
    const domainRows = (result.domain_identity || []).map((item) => [
        escapeHtml(item.check),
        statusPill(item.value, signalTone(item.value)),
        escapeHtml(item.detail),
    ]);
    const cookieIssueRows = (result.cookie_issues || []).map((item) => [
        `<strong>${escapeHtml(item.name)}</strong>`,
        statusPill(item.priority || "P3", String(item.severity || "monitor").toLowerCase()),
        escapeHtml(item.issue),
        escapeHtml(item.is_session_like ? "Session/auth cookie" : "Public cookie"),
    ]);
    const formProbeRows = (result.form_probes || []).map((item) => [
        escapeHtml(item.action || "Unknown action"),
        escapeHtml(item.status_code),
        escapeHtml(item.reflected_input ? "Yes" : "No"),
        escapeHtml(item.detail || ""),
    ]);
    const formInventoryRows = (result.form_inventory || []).map((item) => [
        escapeHtml(item.method || "GET"),
        escapeHtml(item.action || "Unknown action"),
        statusPill(item.status || "Observed only", signalTone(item.status || "")),
        escapeHtml(item.note || ""),
    ]);
    const infraRows = (result.infra || []).map((item) => [
        escapeHtml(item.component),
        escapeHtml(item.detected),
        escapeHtml(item.recommended),
    ]);
    const exposureRows = (result.exposure_findings || []).map((item) => [
        statusPill(item.severity === "high" ? "P2" : "P3", item.severity || "monitor"),
        escapeHtml(item.name),
        escapeHtml(item.evidence || "Not captured"),
        escapeHtml(item.source_url || "Unknown page"),
    ]);
    const seoRows = [
        ["Title", escapeHtml(seo.title || "Not exposed"), escapeHtml(seo.title === "Not exposed" ? "Missing" : "Observed")],
        ["Meta Description", escapeHtml(seo.meta_description || "Not exposed"), escapeHtml(seo.meta_description === "Not exposed" ? "Missing" : "Observed")],
        ["Canonical", escapeHtml(seo.canonical || "Not exposed"), escapeHtml(seo.canonical === "Not exposed" ? "Missing" : "Observed")],
        ["Robots", escapeHtml(seo.robots || "Not exposed"), escapeHtml(seo.robots || "Not exposed")],
        ["Primary H1 Count", escapeHtml(seo.h1_count ?? 0), escapeHtml((seo.h1_count ?? 0) === 1 ? "Healthy" : "Review")],
        ["Images Missing Alt", escapeHtml(seo.images_missing_alt ?? 0), escapeHtml((seo.images_missing_alt ?? 0) === 0 ? "Healthy" : "Review")],
        ["W3C Markup Errors", escapeHtml(markupValidation.errors ?? 0), escapeHtml(markupValidation.checked ? "Validated" : "Not checked")],
        ["W3C Markup Warnings", escapeHtml(markupValidation.warnings ?? 0), escapeHtml(markupValidation.checked ? "Validated" : "Not checked")],
    ];
    const websiteOverviewCards = [
        {
            label: "Audit Scope",
            value: crawlSummary.deep_scan_enabled ? "Deep passive crawl" : "Homepage audit",
            note: `${websiteDetails.pages_reviewed ?? pagesScanned} page(s) reviewed`,
            tone: crawlSummary.deep_scan_enabled ? "monitor" : "info",
        },
        {
            label: "Platform",
            value: websiteDetails.platform || result.platform_name || result.cms,
            note: websiteDetails.version || result.version || "Version not exposed",
            tone: "good",
        },
        {
            label: "Host",
            value: websiteDetails.resolved_hostname || "Not resolved",
            note: websiteDetails.server || "Server not exposed",
            tone: "info",
        },
        {
            label: "Inventory",
            value: `${websiteDetails.components_detected ?? 0} components`,
            note: `${websiteDetails.libraries_detected ?? 0} libraries · ${websiteDetails.forms_reviewed ?? 0} forms`,
            tone: "monitor",
        },
    ];
    const seoScore = typeof seo.score === "number" ? seo.score : null;
    const seoCards = [
        {
            label: "SEO Score",
            value: seoScore != null ? `${seoScore}/100` : "N/A",
            note: `${(seo.issues || []).length} issue(s) identified`,
            tone: scoreTone(seoScore),
            score: seoScore,
        },
        {
            label: "Metadata",
            value: seo.title === "Not exposed" || seo.meta_description === "Not exposed" ? "Needs review" : "Present",
            note: `${seo.title === "Not exposed" ? "Missing title" : "Title found"} · ${seo.meta_description === "Not exposed" ? "Missing meta description" : "Meta description found"}`,
            tone: seo.title === "Not exposed" || seo.meta_description === "Not exposed" ? "high" : "good",
        },
        {
            label: "Canonical and Robots",
            value: seo.canonical === "Not exposed" ? "Needs review" : "Observed",
            note: `Canonical: ${seo.canonical === "Not exposed" ? "missing" : "present"} · Robots: ${seo.robots || "Not exposed"}`,
            tone: seo.canonical === "Not exposed" ? "high" : "monitor",
        },
        {
            label: "Content Structure",
            value: (seo.h1_count ?? 0) === 1 ? "Healthy" : "Needs review",
            note: `H1 count: ${seo.h1_count ?? 0} · Missing alt: ${seo.images_missing_alt ?? 0}`,
            tone: (seo.h1_count ?? 0) === 1 && (seo.images_missing_alt ?? 0) === 0 ? "good" : "monitor",
        },
        {
            label: "Markup Validation",
            value: markupValidation.checked ? `${markupValidation.errors ?? 0} errors` : "Not checked",
            note: markupValidation.checked
                ? `${markupValidation.warnings ?? 0} warnings from W3C validator`
                : (markupValidation.error || "Validator was not available"),
            tone: !markupValidation.checked ? "info" : (markupValidation.errors ?? 0) > 0 ? "high" : (markupValidation.warnings ?? 0) > 0 ? "monitor" : "good",
        },
    ];
    const warningBanner = result.fetch_warning
        ? `
            <section class="card notice-card notice-warning">
                <span class="notice-label">Fetch Warning</span>
                <p>${escapeHtml(result.fetch_warning)}</p>
            </section>
        `
        : "";

    resultsSection.innerHTML = `
        ${warningBanner}
        <section class="summary-grid report-topbar">
            <article class="card metric-card metric-card-platform">
                <span class="metric-label">${escapeHtml(result.platform_label || "Platform Assessment")}</span>
                <strong>${escapeHtml(websiteDetails.platform || result.platform_name || result.cms)}</strong>
                <small>${escapeHtml(result.cms_summary || result.cms)}</small>
            </article>
            <article class="card metric-card metric-card-version">
                <span class="metric-label">Release Track</span>
                <strong>${escapeHtml(result.version)}</strong>
                <small>Recommended: ${escapeHtml(result.recommended_cms_version)}</small>
            </article>
            <article class="card metric-card metric-card-score" style="--score-accent:${scoreColor(result.score)}; --score-accent-soft:${scoreSoftColor(result.score)};">
                <span class="metric-label">Website Score</span>
                <strong>${escapeHtml(result.score)}/100</strong>
                ${renderScoreMeter(result.score)}
                <small>${escapeHtml(result.score_label || scoreModel.benchmark_label || result.risk)} · Weighted from SEO 35%, Performance 35%, Security 30%.</small>
            </article>
            <article class="card metric-card metric-card-export">
                <span class="metric-label">Report</span>
                <strong>Shareable PDF</strong>
                <button type="button" class="report-export-button" data-export-pdf>Export PDF Report</button>
            </article>
        </section>

        <section class="card mt-3">
            <h2>Website Details</h2>
            <p class="muted">Scope, identity, platform profile, and exposure inventory for the audited site.</p>
            <div class="audit-mini-grid">
                ${websiteOverviewCards.map((card) => `
                    <article class="card mini-metric mini-metric-${escapeHtml(card.tone)}">
                        <span class="detail-label">${escapeHtml(card.label)}</span>
                        <strong>${escapeHtml(card.value)}</strong>
                        ${typeof card.score === "number" ? renderScoreMeter(card.score) : ""}
                        <small>${escapeHtml(card.note)}</small>
                    </article>
                `).join("")}
            </div>
            <div class="website-details-grid website-details-grid-strong">
                <article class="detail-note">
                    <strong>Site Identity</strong>
                    <div class="kv-list">
                        <div class="kv-row"><span>Requested</span><strong>${escapeHtml(websiteDetails.requested_url || result.url)}</strong></div>
                        <div class="kv-row"><span>Resolved</span><strong>${escapeHtml(websiteDetails.resolved_url || result.final_url)}</strong></div>
                        <div class="kv-row"><span>Server</span><strong>${escapeHtml(websiteDetails.server || "Not exposed")}</strong></div>
                        <div class="kv-row"><span>Generator</span><strong>${escapeHtml(websiteDetails.meta_generator || "Not exposed")}</strong></div>
                    </div>
                </article>
                <article class="detail-note">
                    <strong>Platform Profile</strong>
                    <div class="kv-list">
                        <div class="kv-row"><span>Primary Platform</span><strong>${escapeHtml(websiteDetails.platform || result.platform_name || result.cms)}</strong></div>
                        <div class="kv-row"><span>Observed Version</span><strong>${escapeHtml(websiteDetails.version || result.version)}</strong></div>
                        <div class="kv-row"><span>Recommended Track</span><strong>${escapeHtml(websiteDetails.recommended_track || result.recommended_cms_version)}</strong></div>
                        <div class="kv-row"><span>CMS Summary</span><strong>${escapeHtml(websiteDetails.cms_summary || result.cms_summary || result.cms)}</strong></div>
                    </div>
                </article>
                <article class="detail-note">
                    <strong>Exposure Inventory</strong>
                    <div class="kv-list">
                        <div class="kv-row"><span>Components Detected</span><strong>${escapeHtml(websiteDetails.components_detected ?? 0)}</strong></div>
                        <div class="kv-row"><span>Libraries Detected</span><strong>${escapeHtml(websiteDetails.libraries_detected ?? 0)}</strong></div>
                        <div class="kv-row"><span>Cookies Observed</span><strong>${escapeHtml(websiteDetails.cookies_observed ?? 0)}</strong></div>
                        <div class="kv-row"><span>Forms Reviewed</span><strong>${escapeHtml(websiteDetails.forms_reviewed ?? 0)}</strong></div>
                    </div>
                </article>
            </div>
            <div class="two-col-grid">
                <article class="card">
                    <h3>Platform Signals</h3>
                    ${renderTable(["Platform", "Role", "Family", "Confidence"], cmsRows)}
                </article>
                <article class="card">
                    <h3>Coverage Note</h3>
                    <div class="detail-note detail-note-plain">
                        <p>${escapeHtml(crawlSummary.coverage_note || "Not captured")}</p>
                    </div>
                </article>
            </div>
            <div class="two-col-grid">
                <article class="card">
                    <h3>${escapeHtml(result.component_label || "Modules / Extensions")}</h3>
                    ${componentRows.length
                        ? renderTable(["Name", "Detected Version", "Recommended"], componentRows)
                        : renderEmptyState("No major public components captured", "The scan did not expose plugin or module names strongly enough to report them here.")}
                </article>
                <article class="card">
                    <h3>Libraries</h3>
                    ${libraryRows.length
                        ? renderTable(["Name", "Detected Version", "Recommended", "CVE Context"], libraryRows)
                        : renderEmptyState("No library fingerprint confirmed", "No JavaScript library version was confidently exposed in public assets on the scanned pages.")}
                </article>
            </div>
        </section>

        <section class="card mt-3">
            <h2>Performance Audit</h2>
            <p class="muted">Mobile and desktop scores are benchmarked against LCP, CLS, FCP, TTFB, INP/TBT, caching, CDN, image, JavaScript, and CSS optimization checks.</p>
            ${performance.warning ? `<div class="detail-note"><strong>Performance Note</strong><p>${escapeHtml(performance.warning)}</p></div>` : ""}
            <div class="detail-note detail-note-plain">
                <p><strong>Weighted Performance Score:</strong> ${escapeHtml(categoryScores.performance != null ? `${categoryScores.performance}/100` : "N/A")}</p>
                <p>Mobile contributes 60% and desktop contributes 40% to the final performance category score.</p>
            </div>
            <div class="perf-grid">
                ${performanceCards}
            </div>
            ${renderTable(["Profile", "Score", "LCP", "FCP", "TTFB", "INP / TBT", "Top Opportunities"], performanceRows)}
            <div class="two-col-grid mt-3">
                <article class="card">
                    <h3>Mobile Benchmark Breakdown</h3>
                    ${renderPerformanceBreakdown("mobile", performance.mobile)}
                </article>
                <article class="card">
                    <h3>Desktop Benchmark Breakdown</h3>
                    ${renderPerformanceBreakdown("desktop", performance.desktop)}
                </article>
            </div>
        </section>

        <section class="card mt-3">
            <h2>Security Audit</h2>
            <p class="muted">Highest-impact security findings and the controls visible from public responses.</p>
            ${renderTable(["Factor", "Priority", "Why It Matters", "Recommended Action", "Impact"], scoreBreakdownRows)}
            <h3 class="mt-3">Recommendations</h3>
            <ul class="recommendations rich-recommendations">
                ${renderRecommendations(result.recommendations || [])}
            </ul>
        </section>

        <section class="card mt-3">
            <h2>Transport, Domain, and Cookie Signals</h2>
            <p class="muted">Visible browser trust, TLS delivery, domain identity, and cookie hardening signals.</p>
            <div class="two-col-grid">
                <article class="card">
                    <h3>Transport and TLS</h3>
                    ${transportRows.length
                        ? renderTable(["Check", "Value", "Detail"], transportRows)
                        : renderEmptyState("No transport data captured", "No transport or TLS detail was available from the scanned response.")}
                </article>
                <article class="card">
                    <h3>Domain Identity</h3>
                    ${domainRows.length
                        ? renderTable(["Check", "Value", "Detail"], domainRows)
                        : renderEmptyState("No domain identity issue captured", "Domain identity checks did not surface a notable issue.")}
                </article>
                <article class="card">
                    <h3>Cookie Issues</h3>
                    ${cookieIssueRows.length
                        ? renderTable(["Cookie", "Priority", "Observed Issue", "Type"], cookieIssueRows)
                        : renderEmptyState("No insecure cookies highlighted", "The scanned responses did not expose a cookie missing Secure, HttpOnly, or SameSite.")}
                </article>
            </div>
        </section>

        <section class="card mt-3">
            <h2>Page Source Leakage</h2>
            <p class="muted">Public markup, scripts, and low-risk form checks that may reveal internal details or unstable handling.</p>
            <div class="two-col-grid">
                <article class="card">
                    <h3>Public Source Exposure</h3>
                    ${exposureRows.length
                        ? renderTable(["Priority", "Finding", "Evidence", "Source"], exposureRows)
                        : renderEmptyState("No public source leakage captured", "No strong debug trace, sensitive comment, source map, or internal environment reference was confirmed.")}
                </article>
                <article class="card">
                    <h3>Security Headers</h3>
                    ${renderTable(["Header", "Purpose", "Detected", "Status"], securityRows)}
                </article>
            </div>
            <div class="two-col-grid mt-3">
                <article class="card">
                    <h3>Forms Discovered</h3>
                    ${formInventoryRows.length
                        ? renderTable(["Method", "Action", "Review Status", "Note"], formInventoryRows)
                        : renderEmptyState("No public form discovered", "No form element was confirmed on the scanned pages.")}
                </article>
                <article class="card">
                    <h3>Forms Probed</h3>
                    ${formProbeRows.length
                        ? renderTable(["Form Action", "Status", "Reflected Input", "Detail"], formProbeRows)
                        : renderEmptyState("No low-risk POST form was probed", crawlSummary.deep_scan_enabled
                            ? "Discovered forms were either GET-only or looked sensitive, so no probe was attempted."
                            : "Enable deep scan if you want the audit to evaluate low-risk same-origin POST forms.")}
                </article>
            </div>
        </section>

        <section class="card mt-3">
            <h2>Technology Categories</h2>
            <p class="muted">Grouped technology evidence across infrastructure, platform, frontend, and business tooling.</p>
            ${renderTechnologySections(result.technology_profile || [])}
            <div class="insight-grid">
                <article class="card">
                    <h3>Edge and Delivery</h3>
                    ${renderEmptyState("Included in category view", "This category is grouped above under Technology Categories when edge and delivery evidence is present.")}
                </article>
                <article class="card">
                    <h3>Infrastructure</h3>
                    ${infraRows.length
                        ? renderTable(["Component", "Detected", "Recommended"], infraRows)
                        : renderEmptyState("No infrastructure marker captured", "The response headers did not expose a recognizable edge or hosting component.")}
                </article>
                <article class="card">
                    <h3>Visibility</h3>
                    <div class="detail-note">
                        <strong>Grouped Sections</strong>
                        <p>Edge and Delivery, Application Platform, Frontend Experience, Analytics and Marketing, Security and Compliance, and Data and Storage are grouped above when public evidence is available.</p>
                    </div>
                </article>
            </div>
        </section>

        <section class="card mt-3">
            <h2>SEO Performance</h2>
            <p class="muted">Homepage SEO hygiene and issues repeated across the scanned page set.</p>
            <div class="audit-mini-grid">
                ${seoCards.map((card) => `
                    <article class="card mini-metric mini-metric-${escapeHtml(card.tone)}">
                        <span class="detail-label">${escapeHtml(card.label)}</span>
                        <strong>${escapeHtml(card.value)}</strong>
                        ${typeof card.score === "number" ? renderScoreMeter(card.score) : ""}
                        <small>${escapeHtml(card.note)}</small>
                    </article>
                `).join("")}
            </div>
            <div class="two-col-grid">
                <article class="card">
                    <h3>SEO Signals</h3>
                    ${renderTable(["Signal", "Observed Value", "Status"], seoRows)}
                </article>
                <article class="card">
                    <h3>SEO Issues</h3>
                    ${renderTable(
                        ["Key SEO Issues"],
                        (seo.issues || []).length ? seo.issues.map((issue) => [escapeHtml(issue)]) : [["No major SEO hygiene issue captured from public markup."]]
                    )}
                </article>
            </div>
            <div class="two-col-grid">
                <article class="card">
                    <h3>W3C Validation</h3>
                    ${markupValidation.checked
                        ? renderTable(
                            ["Top W3C Markup Issues"],
                            (markupValidation.messages || []).length
                                ? markupValidation.messages.map((message) => [escapeHtml(message)])
                                : [["No top W3C markup issue captured."]]
                        )
                        : renderEmptyState("W3C validation unavailable", markupValidation.error || "The validator did not return a result for this URL.")}
                </article>
                <article class="card">
                    <h3>Search Readiness</h3>
                    <div class="detail-note detail-note-plain">
                        <p><strong>Title:</strong> ${escapeHtml(seo.title || "Not exposed")}</p>
                        <p><strong>Canonical:</strong> ${escapeHtml(seo.canonical || "Not exposed")}</p>
                        <p><strong>Robots:</strong> ${escapeHtml(seo.robots || "Not exposed")}</p>
                        <p><strong>Language:</strong> ${escapeHtml(seo.lang || "Not exposed")}</p>
                    </div>
                </article>
            </div>
        </section>
    `;

    latestResult = result;
    if (exportButton) {
        exportButton.hidden = true;
    }
    resultsSection.querySelector("[data-export-pdf]")?.addEventListener("click", exportPdf);
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
    const deepScan = Boolean(deepScanInput?.checked);
    if (!url) {
        setStatus("Enter a website URL to run the audit.", "error");
        return;
    }

    setBusyState(true);
    setStatus(deepScan ? "Running deep passive audit..." : "Running passive audit...", "loading");
    renderLoadingState(url, deepScan);
    latestResult = null;

    try {
        const response = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, deep_scan: deepScan }),
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
