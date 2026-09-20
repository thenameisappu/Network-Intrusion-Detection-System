"""
Flask application factory.
All blueprints registered here — clear single entry point.
"""
import os
import sys

# Add project root to path so 'backend' is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from backend.config import get_config
from backend.database.connection import init_db
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def create_app(config=None) -> Flask:
    app = Flask(__name__)

    # Load configuration
    cfg = config or get_config()
    app.config.from_object(cfg)

    # Create upload folder
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["MODEL_PATH"], exist_ok=True)

    # Extensions
    CORS(app, resources={r"/*": {"origins": app.config["CORS_ORIGINS"]}},
         supports_credentials=True)
    jwt = JWTManager(app)

    # JWT error handlers
    @jwt.unauthorized_loader
    def unauthorized_callback(reason):
        return jsonify({"success": False, "message": "Authentication required.",
                        "error": {"code": "UNAUTHORIZED"}}), 401

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({"success": False, "message": "Token has expired.",
                        "error": {"code": "TOKEN_EXPIRED"}}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(reason):
        return jsonify({"success": False, "message": "Invalid token.",
                        "error": {"code": "INVALID_TOKEN"}}), 401

    # Database
    init_db(app)

    # Register blueprints
    from backend.auth.routes import auth_bp
    from backend.dashboard.routes import dashboard_bp
    from backend.datasets.routes import dataset_bp
    from backend.ml.routes import ml_bp
    from backend.detections.routes import detections_bp
    from backend.alerts.routes import alerts_bp
    from backend.analytics.routes import analytics_bp
    from backend.reports.routes import reports_bp
    from backend.admin.routes import admin_bp
    from backend.network.routes import network_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(dataset_bp)
    app.register_blueprint(ml_bp)
    app.register_blueprint(detections_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(network_bp, name="api_network", url_prefix="/api/network")

    # Health check
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "NIDS API"})

    # Generic error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"success": False, "message": "Endpoint not found.",
                        "error": {"code": "NOT_FOUND"}}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"success": False, "message": "Method not allowed.",
                        "error": {"code": "METHOD_NOT_ALLOWED"}}), 405

    @app.errorhandler(413)
    def request_too_large(e):
        return jsonify({"success": False, "message": "File too large.",
                        "error": {"code": "FILE_TOO_LARGE"}}), 413

    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f"Internal server error: {e}")
        return jsonify({"success": False, "message": "Internal server error.",
                        "error": {"code": "INTERNAL_ERROR"}}), 500

    logger.info("NIDS Flask application created successfully.")
    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
