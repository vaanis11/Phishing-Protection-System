"""
PhishGuard — Advanced Phishing Detection Platform
Flask application entry point.
"""

import re
import os
from flask import Flask, render_template, request, jsonify
from modules.detector import analyze_url
from modules.stats import record_scan, get_stats

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_SORT_KEYS"] = False

# ─── Input Validation ──────────────────────────────────────────────────────────
URL_REGEX = re.compile(
    r'^(https?://)'
    r'([a-zA-Z0-9\-\.@%\_\+~#=]{1,256})'
    r'(\.[a-zA-Z]{2,18})?'
    r'(:\d{1,5})?'
    r'(/[^\s]*)?$'
)

MAX_URL_LENGTH = 2048
MIN_URL_LENGTH = 8

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "No URL provided in request body"}), 400

    url = data["url"].strip()

    if len(url) < MIN_URL_LENGTH:
        return jsonify({"error": "URL is too short to be valid"}), 400

    if len(url) > MAX_URL_LENGTH:
        return jsonify({"error": f"URL exceeds maximum length of {MAX_URL_LENGTH} characters"}), 400

    if not url.startswith(("http://", "https://", "data:")):
        return jsonify({"error": "URL must begin with http://, https://, or data:"}), 400

    # Run analysis
    result = analyze_url(url)

    # Record to stats (non-blocking)
    try:
        record_scan(result)
    except Exception:
        pass

    return jsonify(result)

@app.route("/api/stats", methods=["GET"])
def stats():
    try:
        return jsonify(get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "operational", "engine": "PhishGuard v2.0"})

# ─── Error Handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    # Local/dev runner. For deployment use the Procfile + gunicorn.
    port = int(os.environ.get("PORT", "5001"))
    app.run(debug=True, host="0.0.0.0", port=port)
