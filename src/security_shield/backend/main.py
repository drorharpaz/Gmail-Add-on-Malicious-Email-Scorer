# ---------- Main Application: security-backend/main.py ---------- #
# This file sets up the Flask application that serves as the backend for the Gmail Add-on.
# It initializes the Security Engine and defines the API endpoint for analyzing email metadata.

import os
import sys

from flask import Flask, request, jsonify
from security_shield.backend.engine import SecurityEngine

app = Flask(__name__)

@app.after_request
def apply_hsts(response):
    """Apply HTTP Strict Transport Security (HSTS) headers to all responses.
    This ensures that browsers only connect to the server over HTTPS, enhancing security."""
    
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return response

# Initialize the Security Engine
security_engine = SecurityEngine()

# --- Check Registration Area ---
# Example: security_engine.register_check(IPCheck())
# -------------------------------


@app.route("/health", methods=["GET"])
def health():
    """Liveness and discovery sanity check (GET). Use in Cloud Run or after deploy."""
    names = [c.name for c in security_engine.checks]
    return jsonify({
        "status": "ok",
        "checks_registered": len(security_engine.checks),
        "check_names": names,
    }), 200


@app.route("/debug/checks", methods=["GET"])
def debug_checks():
    """Diagnostics: registered checks, interpreter path, and process working directory."""
    return jsonify({
        "active_checks_count": len(security_engine.checks),
        "check_names": [c.name for c in security_engine.checks],
        "python_path": sys.path,
        "working_directory": os.getcwd(),
    }), 200


@app.route('/analyze', methods=['POST'])
def analyze_email():
    """
    Primary API Endpoint for the Gmail Add-on.
    Routes incoming metadata to the Security Engine.
    """
    try:
        email_metadata = request.get_json()
        
        if not email_metadata:
            return jsonify({"error": "No email metadata received"}), 400

        # Delegate analysis to the engine
        analysis_result = security_engine.execute_analysis(email_metadata)

        return jsonify(analysis_result), 200

    except Exception as e:
        print(f"[SYSTEM ERROR] {str(e)}")
        return jsonify({
            "error": "Internal Analysis Failure",
            "details": str(e)
        }), 500

if __name__ == '__main__':
    # Cloud Run default port
    app.run(host='0.0.0.0', port=8080)