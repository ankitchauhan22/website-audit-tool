from pathlib import Path

from flask import Flask


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https:; "
        "style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data: https://cdnjs.cloudflare.com; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    ),
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def create_app() -> Flask:
    """Create and configure the Flask application."""
    project_root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "public"),
        static_url_path="/static",
    )

    from .views import main_bp

    app.register_blueprint(main_bp)

    @app.after_request
    def apply_security_headers(response):
        """Attach baseline browser hardening headers to every response."""
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    return app
