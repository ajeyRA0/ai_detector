"""
PhishGuard - Web Application Backend
Flask-based REST API and user interface for explainable phishing URL detection.
Operates completely offline on lexical and structural features (never fetches target URLs).
"""

import csv
from datetime import datetime, timezone
import io
import os
import sys
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template, request, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import joblib
import pandas as pd

from feature_extraction import FEATURE_NAMES, explain_features, extract_features

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.joblib")
FEEDBACK_PATH = os.path.join(BASE_DIR, "feedback.csv")
METRICS_PATH = os.path.join(BASE_DIR, "model_metrics.txt")

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

# Application security configurations
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4 MB max payload for bulk uploads

# Rate limiting configured with in-memory storage
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per hour", "100 per minute"],
    storage_uri="memory://",
)

# Global model state
MODEL_BUNDLE: Optional[Dict[str, Any]] = None


def load_model() -> Optional[Dict[str, Any]]:
    """Load persisted model bundle or train if missing."""
    global MODEL_BUNDLE
    if MODEL_BUNDLE is not None:
        return MODEL_BUNDLE

    if not os.path.exists(MODEL_PATH):
        print(f"[*] Model not found at {MODEL_PATH}. Initiating automatic training...")
        from train_model import train
        train(
            dataset_path=os.path.join(BASE_DIR, "sample_dataset.csv"),
            model_output=MODEL_PATH,
            metrics_output=METRICS_PATH,
        )

    try:
        MODEL_BUNDLE = joblib.load(MODEL_PATH)
        print(f"[+] Loaded model: {MODEL_BUNDLE.get('model_name', 'Unknown')}")
    except Exception as e:
        print(f"[!] Failed to load model artifact: {e}", file=sys.stderr)
        MODEL_BUNDLE = None

    return MODEL_BUNDLE


# Ensure model is initialized at startup
load_model()


@app.errorhandler(429)
def ratelimit_handler(e):
    """Graceful JSON response when rate limits are exceeded."""
    return (
        jsonify({
            "error": "Rate limit exceeded. Please wait a moment before sending additional scan requests.",
            "status": 429,
        }),
        429,
    )


@app.errorhandler(400)
def bad_request_handler(e):
    return jsonify({"error": "Bad Request: " + str(e), "status": 400}), 400


@app.errorhandler(500)
def internal_error_handler(e):
    return (
        jsonify({
            "error": "Internal server error occurred during prediction analysis.",
            "status": 500,
        }),
        500,
    )


@app.route("/")
def index():
    """Render main application scan interface."""
    model_bundle = load_model()
    model_name = model_bundle.get("model_name", "Random Forest Classifier") if model_bundle else "Random Forest"
    is_synthetic = model_bundle.get("is_synthetic", True) if model_bundle else True
    return render_template(
        "index.html",
        model_name=model_name,
        is_synthetic=is_synthetic,
    )


@app.route("/model")
def model_page():
    """Render model architecture, metrics, and academic documentation page."""
    model_bundle = load_model()
    metrics = model_bundle.get("metrics", {}) if model_bundle else {}
    importances = model_bundle.get("feature_importances", {}) if model_bundle else {}
    is_synthetic = model_bundle.get("is_synthetic", True) if model_bundle else True

    # Sort importances descending
    sorted_importances = sorted(importances.items(), key=lambda x: x[1], reverse=True)

    return render_template(
        "model.html",
        model_bundle=model_bundle,
        metrics=metrics,
        sorted_importances=sorted_importances,
        is_synthetic=is_synthetic,
        feature_names=FEATURE_NAMES,
    )


@app.route("/api/predict", methods=["POST"])
@limiter.limit("60 per minute")
def api_predict():
    """
    POST /api/predict
    Analyze a single URL and return detailed lexical diagnosis.
    Never visits or fetches the target URL.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON body provided"}), 400

    raw_url = data.get("url")
    if raw_url is None:
        return jsonify({"error": "Missing required field: 'url'"}), 400

    if not isinstance(raw_url, str):
        return jsonify({"error": "'url' must be a valid string"}), 400

    url_str = raw_url.strip()
    if not url_str:
        return jsonify({"error": "URL cannot be empty"}), 400

    if len(url_str) > 2048:
        return jsonify({"error": "URL exceeds maximum permitted length of 2048 characters"}), 400

    model_bundle = load_model()
    if not model_bundle or "model" not in model_bundle:
        return jsonify({"error": "Prediction model is currently unavailable."}), 503

    model = model_bundle["model"]
    model_name = model_bundle.get("model_name", "Random Forest Classifier")
    importances = model_bundle.get("feature_importances", {})

    # Extract 15 features
    features = extract_features(url_str)
    features_df = pd.DataFrame([features], columns=FEATURE_NAMES)

    # Predict probability
    try:
        probabilities = model.predict_proba(features_df)[0]
        # Label 1 is phishing, Label 0 is legitimate
        phishing_prob = float(probabilities[1])
    except Exception:
        # Fallback if binary predict_proba is not standard
        pred = model.predict(features_df)[0]
        phishing_prob = 1.0 if pred == 1 else 0.0

    verdict = "Phishing" if phishing_prob >= 0.5 else "Legitimate"
    confidence_val = phishing_prob if phishing_prob >= 0.5 else (1.0 - phishing_prob)
    confidence_pct = f"{confidence_val * 100:.1f}%"

    reasons = explain_features(features, url_str)

    # Compute risk level badge
    if phishing_prob >= 0.80:
        risk_level = "Severe"
    elif phishing_prob >= 0.50:
        risk_level = "High"
    elif phishing_prob >= 0.25:
        risk_level = "Moderate"
    else:
        risk_level = "Safe"

    response = {
        "url": url_str,
        "verdict": verdict,
        "risk_level": risk_level,
        "phishing_probability": round(phishing_prob, 4),
        "confidence": confidence_pct,
        "features": features,
        "reasons": reasons,
        "importances": importances,
        "model_name": model_name,
    }

    return jsonify(response), 200


@app.route("/api/bulk-predict", methods=["POST"])
@limiter.limit("15 per minute")
def api_bulk_predict():
    """
    POST /api/bulk-predict
    Accepts multiple URLs via JSON or CSV file upload (up to 150 URLs).
    Returns list of prediction verdicts.
    """
    urls_to_scan: List[str] = []

    if request.is_json:
        data = request.get_json(silent=True) or {}
        urls_to_scan = data.get("urls", [])
    elif "file" in request.files:
        uploaded_file = request.files["file"]
        if not uploaded_file.filename:
            return jsonify({"error": "No file selected for bulk upload"}), 400

        content = uploaded_file.stream.read().decode("utf-8", errors="ignore")
        lines = [line.strip() for line in content.splitlines() if line.strip()]

        # Check if CSV has a header
        if lines:
            first_line = lines[0].lower()
            if "url" in first_line:
                lines = lines[1:]
        urls_to_scan = lines
    else:
        # Plain text body with newline-separated URLs
        text_body = request.get_data(as_text=True)
        if text_body:
            urls_to_scan = [line.strip() for line in text_body.splitlines() if line.strip()]

    if not urls_to_scan:
        return jsonify({"error": "No valid URLs provided for bulk analysis."}), 400

    # Limit max bulk size to 150
    urls_to_scan = urls_to_scan[:150]

    model_bundle = load_model()
    if not model_bundle or "model" not in model_bundle:
        return jsonify({"error": "Prediction model is currently unavailable."}), 503

    model = model_bundle["model"]
    results = []

    for item in urls_to_scan:
        url_clean = str(item).strip()
        if not url_clean:
            continue
        if len(url_clean) > 2048:
            results.append({
                "url": url_clean[:60] + "...",
                "verdict": "Error",
                "risk_level": "Invalid",
                "phishing_probability": 0.0,
                "confidence": "N/A",
                "note": "Exceeds max length limit",
            })
            continue

        feats = extract_features(url_clean)
        feats_df = pd.DataFrame([feats], columns=FEATURE_NAMES)
        prob = float(model.predict_proba(feats_df)[0][1])
        verdict = "Phishing" if prob >= 0.5 else "Legitimate"
        conf_val = prob if prob >= 0.5 else (1.0 - prob)

        if prob >= 0.80:
            risk = "Severe"
        elif prob >= 0.50:
            risk = "High"
        elif prob >= 0.25:
            risk = "Moderate"
        else:
            risk = "Safe"

        results.append({
            "url": url_clean,
            "verdict": verdict,
            "risk_level": risk,
            "phishing_probability": round(prob, 4),
            "confidence": f"{conf_val * 100:.1f}%",
        })

    return jsonify({"count": len(results), "results": results}), 200


@app.route("/api/feedback", methods=["POST"])
@limiter.limit("30 per minute")
def api_feedback():
    """
    POST /api/feedback
    Report a URL false positive or false negative. Appends entry to feedback.csv.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True) or {}
    url_reported = str(data.get("url", "")).strip()
    suggested_label = str(data.get("suggested_label", "")).strip().lower()
    notes = str(data.get("notes", "")).strip()

    if not url_reported:
        return jsonify({"error": "Reported URL cannot be empty."}), 400

    if suggested_label not in ["legitimate", "phishing", "safe", "malicious"]:
        return jsonify({"error": "suggested_label must be either 'legitimate' or 'phishing'."}), 400

    # Normalize label
    normalized_label = "phishing" if suggested_label in ["phishing", "malicious"] else "legitimate"
    timestamp = datetime.now(timezone.utc).isoformat()

    file_exists = os.path.exists(FEEDBACK_PATH)
    try:
        with open(FEEDBACK_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "url", "suggested_label", "notes"])
            writer.writerow([timestamp, url_reported, normalized_label, notes])
    except Exception as e:
        return jsonify({"error": f"Failed to record feedback: {e}"}), 500

    return jsonify({
        "status": "success",
        "message": "Thank you! Your feedback has been recorded in feedback.csv for future model retraining.",
        "recorded_at": timestamp,
    }), 200


@app.route("/api/model-info", methods=["GET"])
def api_model_info():
    """Return model summary and feature importances for frontend widgets."""
    model_bundle = load_model()
    if not model_bundle:
        return jsonify({"error": "Model bundle not loaded"}), 503

    return jsonify({
        "model_name": model_bundle.get("model_name"),
        "is_synthetic": model_bundle.get("is_synthetic", True),
        "feature_names": FEATURE_NAMES,
        "feature_importances": model_bundle.get("feature_importances", {}),
        "metrics": model_bundle.get("metrics", {}),
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting PhishGuard development server on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=True)
