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

function renderTable(headers, rows, tableClass = "") {
    if (!rows.length) {
        return '<p class="muted">No data available for this section.</p>';
    }

    const head = headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("");
    const body = rows
        .map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`)
        .join("");

    return `
        <div class="table-wrap">
            <table class="${escapeHtml(tableClass)}">
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

function renderEntityIdentity(name, kind = "tech") {
    const label = String(name || "Unknown").trim() || "Unknown";
    const words = label.split(/\s+/).filter(Boolean);
    const initials = words.slice(0, 2).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || "T";
    return `
        <span class="entity-identity entity-${escapeHtml(kind)}">
            <span class="entity-icon" aria-hidden="true">${escapeHtml(initials)}</span>
            <span>${escapeHtml(label)}</span>
        </span>
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

function renderPerformanceInsightTables(performance) {
    const opportunityRows = ["desktop", "mobile"].flatMap((strategy) => {
        const opportunities = Array.isArray(performance?.[strategy]?.opportunities) ? performance[strategy].opportunities : [];
        return opportunities.map((item) => [
            escapeHtml(strategy[0].toUpperCase() + strategy.slice(1)),
            escapeHtml(item.label || "Opportunity"),
            statusPill(item.impact || "Medium", signalTone(item.impact || "review")),
            escapeHtml(item.detail || "Review this metric in the provider report."),
        ]);
    });

    const diagnosticRows = ["desktop", "mobile"].flatMap((strategy) => {
        const diagnostics = Array.isArray(performance?.[strategy]?.diagnostics) ? performance[strategy].diagnostics : [];
        return diagnostics.map((item) => [
            escapeHtml(strategy[0].toUpperCase() + strategy.slice(1)),
            escapeHtml(item.label || "Diagnostic"),
            escapeHtml(item.value || "Not detected"),
            escapeHtml(item.detail || "Reported by the performance provider."),
        ]);
    });

    return `
        <div class="two-col-grid">
            <article class="card">
                <h3>Top Opportunities</h3>
                ${opportunityRows.length
                    ? renderTable(["Profile", "Opportunity", "Impact", "Detail"], opportunityRows)
                    : renderEmptyState("No major opportunity captured", "The performance provider did not return a high-confidence optimization item for this scan.")}
            </article>
            <article class="card">
                <h3>Diagnostics</h3>
                ${diagnosticRows.length
                    ? renderTable(["Profile", "Diagnostic", "Observed", "Detail"], diagnosticRows)
                    : renderEmptyState("No diagnostics captured", "The performance provider did not return a diagnostic payload for this scan.")}
            </article>
        </div>
    `;
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

function renderTabButton(id, label, active = false) {
    return `<button type="button" class="report-tab${active ? " is-active" : ""}" data-report-tab="${escapeHtml(id)}">${escapeHtml(label)}</button>`;
}

function displayVersion(value) {
    const candidate = String(value || "").trim();
    if (!candidate || candidate === "Not publicly exposed" || candidate === "No CMS release track inferred") {
        return "N/A";
    }
    if (/^\d{4,}$/.test(candidate)) {
        return "N/A";
    }
    return candidate;
}

function renderTabScoreCard(label, score, note = "") {
    const numeric = typeof score === "number" ? score : null;
    return `
        <article class="card tab-score-card" style="--score-accent:${scoreColor(numeric)}; --score-accent-soft:${scoreSoftColor(numeric)};">
            <span class="metric-label">${escapeHtml(label)}</span>
            <strong>${escapeHtml(numeric != null ? `${numeric}/100` : "N/A")}</strong>
            ${renderScoreMeter(numeric)}
            ${note ? `<small>${escapeHtml(note)}</small>` : ""}
        </article>
    `;
}

function renderCompositeTechnologyScore(result, categoryScores, scoreModel) {
    const overall = typeof result.score === "number" ? result.score : null;
    const technologyHealth = typeof categoryScores.technology_health === "number" ? categoryScores.technology_health : null;
    const benchmark = result.score_label || scoreModel?.benchmark_label || result.risk || "";
    return `
        <article class="card metric-card metric-card-score tab-score-card" style="--score-accent:${scoreColor(overall)}; --score-accent-soft:${scoreSoftColor(overall)};">
            <span class="metric-label">Website Score</span>
            <strong>${escapeHtml(overall != null ? `${overall}/100` : "N/A")}</strong>
            ${renderScoreMeter(overall)}
            <small>${escapeHtml(benchmark)}${technologyHealth != null ? ` · Technology Health ${technologyHealth}/100` : ""}</small>
        </article>
    `;
}

function computeInfrastructureScore(result) {
    const transport = result.transport || [];
    const domain = result.domain_identity || [];
    const infra = result.infra || [];
    let achieved = 0;
    let points = 0;

    const https = transport.find((item) => item.check === "HTTPS");
    points += 20;
    achieved += https && String(https.value).toLowerCase() === "enabled" ? 20 : 0;

    const protocol = transport.find((item) => item.check === "HTTP Protocol");
    points += 15;
    if (protocol) {
        const value = String(protocol.value || "").toLowerCase();
        achieved += value.includes("http/3") ? 15 : value.includes("http/2") ? 11 : value.includes("http/1.1") ? 7 : 4;
    }

    const cacheControl = transport.find((item) => item.check === "Cache Control");
    points += 20;
    achieved += cacheControl && !String(cacheControl.value).toLowerCase().includes("not exposed") ? 20 : 6;

    points += 20;
    achieved += infra.length ? 16 : 8;

    const hostConsistency = domain.find((item) => item.check === "Host Consistency");
    points += 15;
    achieved += hostConsistency && String(hostConsistency.value).toLowerCase() === "aligned" ? 15 : 7;

    const serverIdentity = domain.find((item) => item.check === "Server Identity");
    points += 10;
    achieved += serverIdentity && !String(serverIdentity.value).toLowerCase().includes("not exposed") ? 10 : 4;

    return Math.round((achieved / points) * 100);
}

function activateReportTab(tabId) {
    document.querySelectorAll("[data-report-tab]").forEach((button) => {
        button.classList.toggle("is-active", button.getAttribute("data-report-tab") === tabId);
    });
    document.querySelectorAll("[data-tab-panel]").forEach((panel) => {
        panel.hidden = panel.getAttribute("data-tab-panel") !== tabId;
    });
}

function wireReportTabs() {
    const buttons = resultsSection.querySelectorAll("[data-report-tab]");
    if (!buttons.length) {
        return;
    }
    buttons.forEach((button) => {
        button.addEventListener("click", () => activateReportTab(button.getAttribute("data-report-tab")));
    });
    activateReportTab(buttons[0].getAttribute("data-report-tab"));
}

function renderResult(result) {
    const performance = result.performance_audit || {};
    const seo = result.seo_audit || {};
    const markupValidation = seo.markup_validation || {};
    const scoreModel = result.score_model || {};
    const categoryScores = result.category_scores || {};
    const crawlSummary = result.crawl_summary || {};
    const websiteDetails = result.website_details || {};
    const technologySnapshot = result.technology_snapshot || {};
    const technologyDetection = result.technology_detection || {};
    const displayObservedVersion = displayVersion(websiteDetails.version || result.version);
    const displayRecommendedTrack = displayVersion(websiteDetails.recommended_track || result.recommended_cms_version);
    const cmsMatches = Array.isArray(result.cms_matches) ? result.cms_matches : [];
    const pagesScanned = crawlSummary.pages_scanned ?? 1;
    const infrastructureScore = computeInfrastructureScore(result);
    const infrastructureTechRows = (result.technology_stack || [])
        .filter((item) => ["Hosting", "CDN", "Proxy", "Performance"].includes(item.category))
        .map((item) => [
            escapeHtml(item.name),
            escapeHtml(item.category || "Infrastructure"),
            escapeHtml(item.confidence || "Low"),
            escapeHtml(item.evidence || "Public signal observed"),
        ]);
    const componentRows = (result.cms === "WordPress" ? result.plugins : result.modules || [])
        .slice(0, 12)
        .map((item) => [
            escapeHtml(item.name),
            escapeHtml(displayVersion(item.detected_version)),
            escapeHtml(displayVersion(item.recommended_version)),
            escapeHtml(item.source || "public"),
            escapeHtml(item.confidence || "High"),
        ]);
    const libraryRows = (result.libraries || []).slice(0, 20).map((item) => [
        escapeHtml(item.name),
        escapeHtml(displayVersion(item.detected_version)),
        escapeHtml(displayVersion(item.recommended_version)),
        escapeHtml(item.source || "public"),
        escapeHtml(item.confidence || "High"),
        escapeHtml(item.cve_summary || "No CVE summary"),
    ]);
    const cmsRows = (technologySnapshot.secondary_platforms || cmsMatches.filter((item) => String(item.role || "").toLowerCase() !== "primary")).map((item) => [
        renderEntityIdentity(item.name, "platform"),
        escapeHtml(item.role || "Observed"),
        escapeHtml(item.family || "Unknown"),
        escapeHtml(item.confidence || "Observed"),
    ]);
    const primaryEvidenceRows = (technologySnapshot.primary_evidence || []).map((item) => [escapeHtml(item)]);
    const supportingTechnologyRows = (technologySnapshot.supporting_stack || []).map((item) => [
        escapeHtml(item.name),
        escapeHtml(item.category || "Technology"),
        escapeHtml(item.confidence || "Low"),
        escapeHtml(item.evidence || "Public signal observed"),
    ]);
    const endpointProbeRows = Object.entries(technologyDetection.endpoint_probes || {}).map(([path, probe]) => [
        escapeHtml(path),
        escapeHtml(probe.status_code ?? "Not reached"),
        escapeHtml(probe.ok ? "Reached" : "Unavailable"),
        escapeHtml(probe.url || "Not captured"),
    ]);
    const performanceRows = ["mobile", "desktop"].map((strategy) => {
        const audit = performance[strategy] || {};
        const score = audit.benchmark_score ?? audit.score;
        const tone = scoreTone(score);
        return [
            escapeHtml(strategy[0].toUpperCase() + strategy.slice(1)),
            statusPill(score != null ? `${score}/100` : "N/A", tone),
            escapeHtml(audit.performance_score != null ? `${audit.performance_score}/100` : "Not detected"),
            escapeHtml(audit.structure_score != null ? `${audit.structure_score}/100` : "Not detected"),
            escapeHtml(audit.fully_loaded_time || "Not detected"),
            escapeHtml(audit.total_page_size || "Not detected"),
            escapeHtml(audit.total_requests ?? "Not detected"),
            escapeHtml(audit.largest_contentful_paint || "Not available"),
            escapeHtml(audit.cumulative_layout_shift || "Not available"),
            escapeHtml(audit.time_to_first_byte || "Not available"),
            escapeHtml(audit.interactive || "Not available"),
            escapeHtml((audit.recommendations || []).join(", ") || "No major opportunity captured"),
        ];
    });
    const securityBreakdownRows = (result.score_breakdown || [])
        .filter((item) => item.category === "Security")
        .filter((item) => Number(item.impact) !== 0)
        .map((item) => [
            escapeHtml(item.label),
            statusPill(item.priority || "P3", String(item.severity || "monitor").toLowerCase()),
            escapeHtml(item.detail || ""),
            escapeHtml(item.action || ""),
            escapeHtml(item.impact),
        ]);
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
        `<div class="header-detected-clamp">${escapeHtml(item.detected)}</div>`,
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
            note: displayObservedVersion,
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

    const websiteDetailsSection = `
        ${warningBanner}
        <section class="summary-grid report-topbar">
            <article class="card metric-card metric-card-platform">
                <span class="metric-label">${escapeHtml(result.platform_label || "Platform Assessment")}</span>
                <strong>${escapeHtml(websiteDetails.platform || result.platform_name || result.cms)}</strong>
                <small>${escapeHtml(result.cms_summary || result.cms)}</small>
            </article>
            <article class="card metric-card metric-card-version">
                <span class="metric-label">Release Track</span>
                <strong>${escapeHtml(displayObservedVersion)}</strong>
                <small>Recommended: ${escapeHtml(displayRecommendedTrack)}${result.recommended_cms_source ? ` · Source: ${escapeHtml(result.recommended_cms_source)}` : ""}</small>
            </article>
            ${renderCompositeTechnologyScore(result, categoryScores, scoreModel)}
            <article class="card metric-card metric-card-export">
                <span class="metric-label">Report</span>
                <strong>Shareable PDF</strong>
                <button type="button" class="report-export-button" data-export-pdf>Export PDF Report</button>
            </article>
        </section>
        <section class="card mt-3">
            <h2>Technology Profile</h2>
            <p class="muted">A clearer snapshot of the primary platform, the evidence behind it, and the most relevant supporting technologies observed publicly.</p>
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
                    <strong>Scan Scope</strong>
                    <div class="kv-list">
                        <div class="kv-row"><span>Requested</span><strong>${escapeHtml(websiteDetails.requested_url || result.url)}</strong></div>
                        <div class="kv-row"><span>Resolved</span><strong>${escapeHtml(websiteDetails.resolved_url || result.final_url)}</strong></div>
                        <div class="kv-row"><span>Pages Reviewed</span><strong>${escapeHtml(websiteDetails.pages_reviewed ?? pagesScanned)}</strong></div>
                        <div class="kv-row"><span>Server</span><strong>${escapeHtml(websiteDetails.server || "Not exposed")}</strong></div>
                    </div>
                </article>
                <article class="detail-note">
                    <strong>Primary Platform Assessment</strong>
                    <div class="kv-list">
                        <div class="kv-row"><span>Primary Platform</span><strong>${escapeHtml(websiteDetails.platform || result.platform_name || result.cms)}</strong></div>
                        <div class="kv-row"><span>Detection Confidence</span><strong>${escapeHtml(websiteDetails.platform_confidence || technologySnapshot.primary_confidence || "Low")}</strong></div>
                        <div class="kv-row"><span>Observed Version</span><strong>${escapeHtml(displayObservedVersion)}</strong></div>
                        <div class="kv-row"><span>Recommended Track</span><strong>${escapeHtml(displayRecommendedTrack)}</strong></div>
                        <div class="kv-row"><span>Summary</span><strong>${escapeHtml(websiteDetails.cms_summary || result.cms_summary || result.cms)}</strong></div>
                    </div>
                </article>
                <article class="detail-note">
                    <strong>Profile Inventory</strong>
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
                    <h3>Why This Platform Was Chosen</h3>
                    ${primaryEvidenceRows.length
                        ? renderTable(["Observed Public Evidence"], primaryEvidenceRows)
                        : renderEmptyState("No strong primary evidence captured", "The scan inferred the primary platform from the broader public technology pattern rather than a single exposed vendor marker.")}
                </article>
                <article class="card">
                    <h3>Secondary Platform Signals</h3>
                    ${cmsRows.length
                        ? renderTable(["Platform", "Role", "Family", "Confidence"], cmsRows)
                        : renderEmptyState("No secondary platform signal retained", "No second CMS or platform marker was strong enough to report separately from the primary platform.")}
                </article>
            </div>
            <div class="two-col-grid">
                <article class="card">
                    <h3>${escapeHtml(result.component_label || "Modules / Extensions")}</h3>
                    ${componentRows.length
                        ? renderTable(["Name", "Detected Version", "Recommended", "Source", "Confidence"], componentRows)
                        : renderEmptyState("No major public components captured", "The scan did not expose plugin or module names strongly enough to report them here.")}
                </article>
                <article class="card">
                    <h3>Libraries</h3>
                    ${libraryRows.length
                        ? renderTable(["Library", "Detected Version", "Recommended", "Source", "Confidence", "CVE Context"], libraryRows)
                        : renderEmptyState("No library fingerprint confirmed", "Only true client-side libraries are shown here. Frameworks and broader platform signals are kept in the supporting technology area instead of being mixed into this table.")}
                </article>
            </div>
            <div class="two-col-grid">
                <article class="card">
                    <h3>Supporting Technology Signals</h3>
                    ${supportingTechnologyRows.length
                        ? renderTable(["Technology", "Category", "Confidence", "Evidence"], supportingTechnologyRows)
                        : renderEmptyState("No distinct supporting signal retained", "Technologies already shown under platform, components, or libraries were not repeated here.")}
                </article>
                <article class="card">
                    <h3>Endpoint Probes</h3>
                    ${endpointProbeRows.length
                        ? renderTable(["Endpoint", "Status", "Result", "Final URL"], endpointProbeRows)
                        : renderEmptyState("No endpoint probe data captured", "Common CMS and feed endpoints were not probed for this scan.")}
                </article>
            </div>
            <div class="two-col-grid">
                <article class="card">
                    <h3>Coverage and Source Mix</h3>
                    <div class="detail-note detail-note-plain">
                        <p>${escapeHtml(crawlSummary.coverage_note || "Not captured")}</p>
                        <p><strong>Generator:</strong> ${escapeHtml(websiteDetails.meta_generator || "Not exposed")}</p>
                        <p><strong>Component sources:</strong> Public ${escapeHtml(technologySnapshot.component_source_summary?.public ?? 0)} · Merged ${escapeHtml(technologySnapshot.component_source_summary?.merged ?? 0)} · External ${escapeHtml(technologySnapshot.component_source_summary?.external ?? 0)}</p>
                        <p><strong>Library sources:</strong> Public ${escapeHtml(technologySnapshot.library_source_summary?.public ?? 0)} · Merged ${escapeHtml(technologySnapshot.library_source_summary?.merged ?? 0)} · External ${escapeHtml(technologySnapshot.library_source_summary?.external ?? 0)}</p>
                    </div>
                </article>
                <article class="card">
                    <h3>Detection Method</h3>
                    <div class="detail-note detail-note-plain">
                        <p>Pattern matching uses public HTML, headers, linked assets, cookies, and targeted endpoint probes. No deprecated JS runtime is used.</p>
                    </div>
                </article>
            </div>
        </section>
    `;

    const performanceSection = `
        <div class="tab-score-strip">
            ${renderTabScoreCard("Performance Score", categoryScores.performance, "Desktop and mobile combined with a 60/40 weighting.")}
        </div>
        <section class="card">
            <h2>Performance Audit</h2>
            <p class="muted">Real browser-based performance data is sourced from GTmetrix when configured, with Pingdom or heuristic fallback only when live provider testing is unavailable.</p>
            ${performance.warning ? `<div class="detail-note"><strong>Performance Note</strong><p>${escapeHtml(performance.warning)}</p></div>` : ""}
            ${renderTable(["Profile", "Score", "Performance", "Structure", "Fully Loaded", "Page Size", "Requests", "LCP", "CLS", "TTFB", "TBT", "Top Opportunities"], performanceRows)}
            ${renderPerformanceInsightTables(performance)}
        </section>
    `;

    const securitySection = `
        <div class="tab-score-strip">
            ${renderTabScoreCard("Security Score", categoryScores.security, "Headers, TLS, cookies, leakage, and vulnerability posture.")}
        </div>
        <section class="card">
            <h2>Security Audit</h2>
            <p class="muted">Highest-impact security findings and the controls visible from public responses.</p>
            ${securityBreakdownRows.length
                ? renderTable(["Factor", "Priority", "Why It Matters", "Recommended Action", "Impact"], securityBreakdownRows)
                : renderEmptyState("No security score factor captured", "No security-specific scoring factor was retained for this scan.")}
            <h3 class="mt-3">Recommendations</h3>
            <ul class="recommendations rich-recommendations">
                ${renderRecommendations(result.recommendations || [])}
            </ul>
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
                    ${renderTable(["Header", "Purpose", "Detected", "Status"], securityRows, "security-headers-table")}
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
    `;

    const infrastructureSection = `
        <div class="tab-score-strip">
            ${renderTabScoreCard("Infrastructure Score", infrastructureScore, "Transport, protocol, caching, hosting, and delivery signals.")}
        </div>
        <section class="card">
            <h2>Transport, Domain, and Cookie Signals</h2>
            <p class="muted">Visible browser trust, TLS delivery, domain identity, protocol support, and cookie hardening signals.</p>
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
            <h2>Infrastructure Signals</h2>
            <p class="muted">Hosting, CDN, proxy, cache, and edge-delivery evidence only.</p>
            <div class="two-col-grid">
                <article class="card">
                    <h3>Observed Infrastructure</h3>
                    ${infraRows.length
                        ? renderTable(["Component", "Detected", "Recommended"], infraRows)
                        : renderEmptyState("No infrastructure marker captured", "The response headers did not expose a recognizable edge or hosting component.")}
                </article>
                <article class="card">
                    <h3>Infrastructure Technology Evidence</h3>
                    ${infrastructureTechRows.length
                        ? renderTable(["Technology", "Type", "Confidence", "Evidence"], infrastructureTechRows)
                        : renderEmptyState("No infrastructure technology signal retained", "Only infrastructure-related technologies appear here. Non-infrastructure technologies are kept in other sections.")}
                </article>
            </div>
        </section>
    `;

    const seoSection = `
        <div class="tab-score-strip">
            ${renderTabScoreCard("SEO Score", categoryScores.seo, "Metadata, crawlability, content structure, and validation.")}
        </div>
        <section class="card">
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

    resultsSection.innerHTML = `
        <section class="report-tabs-shell mt-3">
            <div class="report-tabs" role="tablist" aria-label="Audit report sections">
                ${renderTabButton("website", "Technology Profile", true)}
                ${renderTabButton("security", "Security")}
                ${renderTabButton("performance", "Performance")}
                ${renderTabButton("infrastructure", "Infrastructure")}
                ${renderTabButton("seo", "SEO")}
            </div>
            <div class="report-tab-panel" data-tab-panel="website">${websiteDetailsSection}</div>
            <div class="report-tab-panel" data-tab-panel="security" hidden>${securitySection}</div>
            <div class="report-tab-panel" data-tab-panel="performance" hidden>${performanceSection}</div>
            <div class="report-tab-panel" data-tab-panel="infrastructure" hidden>${infrastructureSection}</div>
            <div class="report-tab-panel" data-tab-panel="seo" hidden>${seoSection}</div>
        </section>
    `;

    latestResult = result;
    if (exportButton) {
        exportButton.hidden = true;
    }
    resultsSection.querySelector("[data-export-pdf]")?.addEventListener("click", exportPdf);
    wireReportTabs();
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
        const contentType = response.headers.get("content-type") || "";
        const result = contentType.includes("application/json")
            ? await response.json()
            : { error: await response.text() };

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
