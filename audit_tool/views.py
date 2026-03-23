import os
import tempfile

from flask import Blueprint, after_this_request, jsonify, render_template, request, send_file

from pdf.report_generator import generate_pdf
from scanner import run_scan


main_bp = Blueprint("main", __name__)


@main_bp.route("/", methods=["GET"])
def index():
    """Render the single-page audit interface."""
    return render_template("index.html")


@main_bp.route("/scan", methods=["POST"])
def scan():
    """Run the passive audit for the submitted URL."""
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    deep_scan = bool(payload.get("deep_scan"))
    if not url:
        return jsonify({"error": "Enter a website URL to run the audit."}), 400

    result = run_scan(url, deep_scan=deep_scan)
    status_code = 200 if not result.get("error") else 502
    return jsonify(result), status_code


@main_bp.route("/export-pdf", methods=["POST"])
def export_pdf():
    """Generate and stream a PDF version of the audit report."""
    payload = request.get_json(silent=True) or {}
    if not payload:
        return jsonify({"error": "Scan results are required to export a PDF."}), 400

    fd, output_path = tempfile.mkstemp(prefix="website-audit-", suffix=".pdf")
    os.close(fd)
    generate_pdf(payload, output_path=output_path)

    @after_this_request
    def cleanup(response):
        try:
            os.remove(output_path)
        except OSError:
            pass
        return response

    return send_file(
        output_path,
        as_attachment=True,
        download_name="website-audit-report.pdf",
        mimetype="application/pdf",
    )
