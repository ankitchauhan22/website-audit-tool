from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


PDF_THEME = {
    "ink": colors.HexColor("#152033"),
    "muted": colors.HexColor("#5d677b"),
    "line": colors.HexColor("#d9d6cf"),
    "panel": colors.HexColor("#f8f6f1"),
    "panel_alt": colors.HexColor("#eef4f7"),
    "accent": colors.HexColor("#124e78"),
    "accent_soft": colors.HexColor("#dbeaf4"),
    "must": colors.HexColor("#b42318"),
    "high": colors.HexColor("#b45309"),
    "monitor": colors.HexColor("#155e75"),
    "good": colors.HexColor("#157347"),
}


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=PDF_THEME["ink"],
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BodyMuted",
            parent=styles["BodyText"],
            fontSize=9.5,
            leading=13,
            textColor=PDF_THEME["muted"],
        )
    )
    styles.add(
        ParagraphStyle(
            name="MetricValue",
            parent=styles["Heading3"],
            fontSize=17,
            leading=20,
            textColor=PDF_THEME["ink"],
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="MetricLabel",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=11,
            textColor=PDF_THEME["muted"],
            uppercase=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SmallCell",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=11,
            textColor=PDF_THEME["ink"],
        )
    )
    return styles


def _severity_color(severity: str):
    mapping = {
        "must": "#b42318",
        "high": "#b45309",
        "monitor": "#155e75",
        "good": "#157347",
    }
    return mapping.get((severity or "").lower(), "#155e75")


def _score_hex(score) -> str:
    if not isinstance(score, (int, float)):
        return "#94a3b8"
    if score >= 90:
        return "#16A34A"
    if score >= 70:
        return "#4ADE80"
    if score >= 50:
        return "#F97316"
    if score >= 30:
        return "#EF4444"
    return "#7F1D1D"


def _paragraph(value, styles, style_name="BodyText"):
    return Paragraph(str(value or "Not available"), styles[style_name])


def _section_intro(title: str, intro: str, styles):
    return [
        Paragraph(title, styles["SectionTitle"]),
        Paragraph(intro, styles["BodyMuted"]),
        Spacer(1, 6),
    ]


def _build_table(rows, col_widths, header_fill=PDF_THEME["accent"], zebra=True, has_header=True):
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.5, PDF_THEME["line"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    if has_header:
        commands.extend(
            [
                ("BACKGROUND", (0, 0), (-1, 0), header_fill),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("TOPPADDING", (0, 0), (-1, 0), 8),
            ]
        )
    table.setStyle(TableStyle(commands))
    if zebra and ((has_header and len(rows) > 1) or (not has_header and len(rows) > 0)):
        table.setStyle(
            TableStyle(
                [
                    (
                        "ROWBACKGROUNDS",
                        (0, 1 if has_header else 0),
                        (-1, -1),
                        [colors.white, PDF_THEME["panel"]],
                    ),
                ]
            )
        )
    return table


def _metric_cards(data, styles):
    cards = [
        [
            _paragraph("Detected Platform", styles, "MetricLabel"),
            _paragraph(data.get("platform_name", data.get("cms", "Not available")), styles, "MetricValue"),
            _paragraph(data.get("cms_summary", data.get("cms", "Not available")), styles, "BodyMuted"),
        ],
        [
            _paragraph("Detected Version", styles, "MetricLabel"),
            _paragraph(data.get("version", "Not publicly exposed"), styles, "MetricValue"),
            _paragraph(f"Recommended track: {data.get('recommended_cms_version', 'No CMS release track inferred')}", styles, "BodyMuted"),
        ],
        [
            _paragraph("Health Score", styles, "MetricLabel"),
            Paragraph(f'<font color="{_score_hex(data.get("score", 0))}">{data.get("score", 0)}/100</font>', styles["MetricValue"]),
            _paragraph(f"Risk: {data.get('risk', 'Unknown')}", styles, "BodyMuted"),
        ],
    ]

    table = Table(cards, colWidths=[58 * mm, 58 * mm, 58 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.8, PDF_THEME["line"]),
                ("INNERGRID", (0, 0), (-1, -1), 0.8, PDF_THEME["line"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("BACKGROUND", (0, 0), (0, 0), PDF_THEME["panel"]),
                ("BACKGROUND", (1, 0), (1, 0), PDF_THEME["panel_alt"]),
                ("BACKGROUND", (2, 0), (2, 0), colors.white),
            ]
        )
    )
    return table


def _recommendation_rows(data, styles):
    rows = [[
        _paragraph("Priority", styles, "SmallCell"),
        _paragraph("Recommendation", styles, "SmallCell"),
        _paragraph("Evidence", styles, "SmallCell"),
    ]]
    for recommendation in data.get("recommendations", []):
        if isinstance(recommendation, dict):
            severity = recommendation.get("severity", "monitor").upper()
            title = recommendation.get("title", "Recommendation")
            action = recommendation.get("action", "")
            evidence = recommendation.get("evidence", "")
            priority = Paragraph(
                f'<font color="{_severity_color(recommendation.get("severity"))}"><b>{severity}</b></font>',
                styles["SmallCell"],
            )
            rows.append(
                [
                    priority,
                    _paragraph(f"<b>{title}</b><br/>{action}", styles, "SmallCell"),
                    _paragraph(evidence or "No additional evidence captured.", styles, "SmallCell"),
                ]
            )
        else:
            rows.append(
                [
                    _paragraph("MONITOR", styles, "SmallCell"),
                    _paragraph(recommendation, styles, "SmallCell"),
                    _paragraph("Generated from passive audit output.", styles, "SmallCell"),
                ]
            )
    return rows


def _score_rows(data, styles):
    rows = [[
        _paragraph("Factor", styles, "SmallCell"),
        _paragraph("Priority", styles, "SmallCell"),
        _paragraph("Why It Matters", styles, "SmallCell"),
        _paragraph("Recommended Action", styles, "SmallCell"),
        _paragraph("Impact", styles, "SmallCell"),
    ]]
    for item in data.get("score_breakdown", []):
        if not item.get("impact"):
            continue
        rows.append(
            [
                _paragraph(item.get("label", "Unspecified factor"), styles, "SmallCell"),
                _paragraph(item.get("priority", "P3"), styles, "SmallCell"),
                _paragraph(item.get("detail", "No explanation available."), styles, "SmallCell"),
                _paragraph(item.get("action", "Review this factor manually."), styles, "SmallCell"),
                _paragraph(str(item.get("impact", 0)), styles, "SmallCell"),
            ]
        )
    return rows


def _compact_rows(items, headers, keys, styles):
    rows = [[_paragraph(header, styles, "SmallCell") for header in headers]]
    for item in items:
        rows.append([_paragraph(item.get(key, "Not available"), styles, "SmallCell") for key in keys])
    return rows


def generate_pdf(data, output_path="audit_report.pdf"):
    """Generate a more structured PDF export from the audit result payload."""
    styles = _build_styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        title="Website Audit Report",
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
    )

    story = [
        Paragraph("Website Audit Report", styles["Title"]),
        Spacer(1, 4),
        Paragraph(
            "A passive assessment of externally visible platform, security, transport, component, and lifecycle signals.",
            styles["BodyMuted"],
        ),
        Spacer(1, 12),
        _metric_cards(data, styles),
        Spacer(1, 12),
    ]

    if data.get("fetch_warning"):
        story.extend(
            _section_intro(
                "Fetch Warning",
                "The target was reachable, but the fetch path required special handling that may affect confidence.",
                styles,
            )
        )
        warning_table = _build_table(
            [[_paragraph("Warning", styles, "SmallCell")], [_paragraph(data["fetch_warning"], styles, "SmallCell")]],
            [180 * mm],
            header_fill=PDF_THEME["high"],
            zebra=False,
            has_header=False,
        )
        story.extend([warning_table, Spacer(1, 12)])

    story.extend(
        _section_intro(
            "Website Details",
            "This section captures the resolved site, platform conclusion, and the coverage used to produce the audit.",
            styles,
        )
    )
    summary_rows = [
        [_paragraph("Requested URL", styles, "SmallCell"), _paragraph(data.get("url", "Not available"), styles, "SmallCell")],
        [_paragraph("Final URL", styles, "SmallCell"), _paragraph(data.get("final_url", data.get("url", "Not available")), styles, "SmallCell")],
        [_paragraph("Deep Scan", styles, "SmallCell"), _paragraph("Enabled" if (data.get("crawl_summary") or {}).get("deep_scan_enabled") else "Off", styles, "SmallCell")],
        [_paragraph("Pages Scanned", styles, "SmallCell"), _paragraph(str((data.get("crawl_summary") or {}).get("pages_scanned", 1)), styles, "SmallCell")],
        [_paragraph("Platform Assessment", styles, "SmallCell"), _paragraph(data.get("cms_summary", data.get("cms", "Not available")), styles, "SmallCell")],
        [_paragraph("Detected Version", styles, "SmallCell"), _paragraph(data.get("version", "Not publicly exposed"), styles, "SmallCell")],
        [_paragraph("Recommended Track", styles, "SmallCell"), _paragraph(data.get("recommended_cms_version", "No CMS release track inferred"), styles, "SmallCell")],
        [_paragraph("Health Score", styles, "SmallCell"), _paragraph(f"{data.get('score', 0)}/100 ({data.get('risk', 'Unknown')})", styles, "SmallCell")],
    ]
    story.extend([_build_table(summary_rows, [48 * mm, 132 * mm], header_fill=PDF_THEME["accent_soft"], zebra=False, has_header=False), Spacer(1, 12)])

    if data.get("recommendations"):
        story.extend(
            _section_intro(
                "Priority Actions",
                "Recommendations are grouped by urgency so teams can separate immediate remediation from follow-up verification work.",
                styles,
            )
        )
        story.extend([_build_table(_recommendation_rows(data, styles), [20 * mm, 95 * mm, 65 * mm]), Spacer(1, 12)])

    if data.get("score_breakdown"):
        story.extend(
            _section_intro(
                "Security Audit",
                "This section focuses on the scored security and transport issues that most affect the current health posture.",
                styles,
            )
        )
        story.extend([_build_table(_score_rows(data, styles), [42 * mm, 20 * mm, 58 * mm, 48 * mm, 15 * mm]), Spacer(1, 12)])

    performance = data.get("performance_audit") or {}
    if performance.get("mobile") or performance.get("desktop") or performance.get("error"):
        story.extend(
            _section_intro(
                "Performance Audit",
                "PageSpeed results are shown for mobile and desktop when the public PSI API could complete the analysis.",
                styles,
            )
        )
        if performance.get("error"):
            story.extend([_build_table([[_paragraph(performance["error"], styles, "SmallCell")]], [180 * mm], has_header=False), Spacer(1, 12)])
        else:
            perf_rows = [[
                _paragraph("Profile", styles, "SmallCell"),
                _paragraph("Score", styles, "SmallCell"),
                _paragraph("Performance", styles, "SmallCell"),
                _paragraph("Structure", styles, "SmallCell"),
                _paragraph("Fully Loaded", styles, "SmallCell"),
                _paragraph("Page Size", styles, "SmallCell"),
                _paragraph("Requests", styles, "SmallCell"),
                _paragraph("LCP", styles, "SmallCell"),
                _paragraph("CLS", styles, "SmallCell"),
                _paragraph("TTFB", styles, "SmallCell"),
                _paragraph("TBT", styles, "SmallCell"),
                _paragraph("Top Opportunities", styles, "SmallCell"),
            ]]
            for strategy in ("mobile", "desktop"):
                audit = performance.get(strategy) or {}
                score_value = audit.get("score")
                perf_rows.append(
                    [
                        _paragraph(strategy.title(), styles, "SmallCell"),
                        Paragraph(f'<font color="{_score_hex(score_value)}">{score_value if score_value is not None else "N/A"}</font>', styles["SmallCell"]),
                        _paragraph(audit.get("performance_score", "Not detected"), styles, "SmallCell"),
                        _paragraph(audit.get("structure_score", "Not detected"), styles, "SmallCell"),
                        _paragraph(audit.get("fully_loaded_time", "Not detected"), styles, "SmallCell"),
                        _paragraph(audit.get("total_page_size", "Not detected"), styles, "SmallCell"),
                        _paragraph(str(audit.get("total_requests", "Not detected")), styles, "SmallCell"),
                        _paragraph(audit.get("largest_contentful_paint", "Not available"), styles, "SmallCell"),
                        _paragraph(audit.get("cumulative_layout_shift", "Not available"), styles, "SmallCell"),
                        _paragraph(audit.get("time_to_first_byte", "Not available"), styles, "SmallCell"),
                        _paragraph(audit.get("interactive", "Not available"), styles, "SmallCell"),
                        _paragraph(", ".join(audit.get("recommendations", [])) or "No major opportunity captured", styles, "SmallCell"),
                    ]
                )
            story.extend([_build_table(perf_rows, [18 * mm, 16 * mm, 18 * mm, 18 * mm, 21 * mm, 21 * mm, 16 * mm, 16 * mm, 14 * mm, 16 * mm, 14 * mm, 38 * mm]), Spacer(1, 12)])

    seo = data.get("seo_audit") or {}
    if seo:
        story.extend(
            _section_intro(
                "SEO Performance",
                "Homepage SEO hygiene and repeated issues from the scanned page set are summarized below.",
                styles,
            )
        )
        seo_rows = [
            [_paragraph("Signal", styles, "SmallCell"), _paragraph("Observed", styles, "SmallCell")],
            [_paragraph("Title", styles, "SmallCell"), _paragraph(seo.get("title", "Not exposed"), styles, "SmallCell")],
            [_paragraph("Meta Description", styles, "SmallCell"), _paragraph(seo.get("meta_description", "Not exposed"), styles, "SmallCell")],
            [_paragraph("Canonical", styles, "SmallCell"), _paragraph(seo.get("canonical", "Not exposed"), styles, "SmallCell")],
            [_paragraph("Robots", styles, "SmallCell"), _paragraph(seo.get("robots", "Not exposed"), styles, "SmallCell")],
            [_paragraph("H1 Count", styles, "SmallCell"), _paragraph(str(seo.get("h1_count", 0)), styles, "SmallCell")],
            [_paragraph("Images Missing Alt", styles, "SmallCell"), _paragraph(str(seo.get("images_missing_alt", 0)), styles, "SmallCell")],
        ]
        story.extend([_build_table(seo_rows, [48 * mm, 132 * mm], has_header=True), Spacer(1, 8)])
        if seo.get("issues"):
            issue_rows = [[_paragraph("Key SEO Issues", styles, "SmallCell")]] + [[_paragraph(issue, styles, "SmallCell")] for issue in seo["issues"][:6]]
            story.extend([_build_table(issue_rows, [180 * mm], has_header=False), Spacer(1, 12)])

    if data.get("cms_matches"):
        story.extend(
            _section_intro(
                "CMS Detection",
                "Primary and secondary CMS conclusions are ranked from passive evidence only and should be validated against internal ownership records.",
                styles,
            )
        )
        cms_rows = _compact_rows(
            data["cms_matches"],
            ["Platform", "Role", "Family", "Confidence"],
            ["name", "role", "family", "confidence"],
            styles,
        )
        story.extend([_build_table(cms_rows, [55 * mm, 25 * mm, 55 * mm, 45 * mm]), Spacer(1, 12)])

    if data.get("security") or data.get("transport"):
        story.extend(
            _section_intro(
                "Security and Transport",
                "These controls influence browser trust, transport security, and session protection for visitors.",
                styles,
            )
        )
        if data.get("security"):
            security_rows = [[
                _paragraph("Header", styles, "SmallCell"),
                _paragraph("Purpose", styles, "SmallCell"),
                _paragraph("Detected", styles, "SmallCell"),
                _paragraph("Status", styles, "SmallCell"),
            ]]
            for item in data["security"]:
                security_rows.append(
                    [
                        _paragraph(item.get("header"), styles, "SmallCell"),
                        _paragraph(item.get("parameter"), styles, "SmallCell"),
                        _paragraph(item.get("detected"), styles, "SmallCell"),
                        _paragraph(item.get("status"), styles, "SmallCell"),
                    ]
                )
            story.extend([_build_table(security_rows, [38 * mm, 62 * mm, 45 * mm, 35 * mm]), Spacer(1, 8)])
        if data.get("transport"):
            transport_rows = [[
                _paragraph("Check", styles, "SmallCell"),
                _paragraph("Value", styles, "SmallCell"),
                _paragraph("Detail", styles, "SmallCell"),
            ]]
            for item in data["transport"]:
                transport_rows.append(
                    [
                        _paragraph(item.get("check"), styles, "SmallCell"),
                        _paragraph(item.get("value"), styles, "SmallCell"),
                        _paragraph(item.get("detail"), styles, "SmallCell"),
                    ]
                )
            story.extend([_build_table(transport_rows, [35 * mm, 35 * mm, 110 * mm]), Spacer(1, 12)])

    if data.get("plugins") or data.get("modules") or data.get("libraries"):
        story.extend(
            _section_intro(
                "Components and Libraries",
                "Public component paths help estimate patching surface area, but versions may still need internal confirmation when not exposed externally.",
                styles,
            )
        )
        inventory = []
        for item in data.get("plugins", []):
            inventory.append({"type": "Plugin", "name": item["name"], "version": item.get("detected_version", "Not publicly exposed"), "recommended": item.get("recommended_version", "Current supported release")})
        for item in data.get("modules", []):
            inventory.append({"type": "Module", "name": item["name"], "version": item.get("detected_version", "Not publicly exposed"), "recommended": item.get("recommended_version", "Current supported release")})
        for item in data.get("libraries", []):
            inventory.append({"type": "Library", "name": item["name"], "version": item.get("detected_version", "Not publicly exposed"), "recommended": item.get("recommended_version", "Current supported release")})
        component_rows = _compact_rows(
            inventory,
            ["Type", "Name", "Detected Version", "Recommended"],
            ["type", "name", "version", "recommended"],
            styles,
        )
        story.extend([_build_table(component_rows, [24 * mm, 56 * mm, 45 * mm, 55 * mm]), Spacer(1, 12)])

    if data.get("technology_stack"):
        story.extend(
            _section_intro(
                "Technology Signal Appendix",
                "This appendix lists the broader technology evidence that informed the summary and remediation guidance.",
                styles,
            )
        )
        tech_rows = [[
            _paragraph("Category", styles, "SmallCell"),
            _paragraph("Technology", styles, "SmallCell"),
            _paragraph("Lifecycle", styles, "SmallCell"),
            _paragraph("Detected Version", styles, "SmallCell"),
            _paragraph("Recommended Track", styles, "SmallCell"),
        ]]
        for item in data["technology_stack"]:
            tech_rows.append(
                [
                    _paragraph(item.get("category"), styles, "SmallCell"),
                    _paragraph(item.get("name"), styles, "SmallCell"),
                    _paragraph(item.get("status", "Observed"), styles, "SmallCell"),
                    _paragraph(item.get("detected_version", "Not publicly exposed"), styles, "SmallCell"),
                    _paragraph(item.get("recommended_track", "No structured release track"), styles, "SmallCell"),
                ]
            )
        story.extend([_build_table(tech_rows, [28 * mm, 42 * mm, 28 * mm, 38 * mm, 44 * mm])])

    doc.build(story)
    return output_path
