"""
Unit and Integration tests for PhishGuard Flask Web Application & REST API.
Tests endpoints: /api/predict, /api/bulk-predict, /api/feedback, /api/model-info, /, /model.
"""

import json
import os
import tempfile
import pytest
from web_app import app, FEEDBACK_PATH


@pytest.fixture
def client():
    """Create Flask test client with testing configurations."""
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def test_index_route(client):
    """Ensure homepage renders successfully with HTTP 200."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"PhishGuard" in response.data
    assert b"Analyze URL" in response.data


def test_model_route(client):
    """Ensure model documentation page renders with HTTP 200."""
    response = client.get("/model")
    assert response.status_code == 200
    assert b"Confusion Matrices" in response.data
    assert b"Random Forest" in response.data
    assert b"Viva Voce Defense" in response.data


def test_predict_legitimate_url(client):
    """Test API prediction on a clearly legitimate URL."""
    payload = {"url": "https://www.google.com"}
    response = client.post(
        "/api/predict",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert response.status_code == 200
    data = response.get_json()

    assert "verdict" in data
    assert "phishing_probability" in data
    assert "confidence" in data
    assert "features" in data
    assert "reasons" in data
    assert "importances" in data
    assert "model_name" in data

    assert data["verdict"] == "Legitimate"
    assert data["phishing_probability"] < 0.5
    assert len(data["features"]) == 15


def test_predict_phishing_url(client):
    """Test API prediction on a characteristic phishing URL."""
    payload = {"url": "http://192.168.1.1/paypal-update/verification.php?login=1"}
    response = client.post(
        "/api/predict",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert response.status_code == 200
    data = response.get_json()

    assert data["verdict"] == "Phishing"
    assert data["phishing_probability"] >= 0.5
    assert data["risk_level"] in ["High", "Severe"]
    assert len(data["reasons"]) > 0


def test_predict_empty_url_returns_400(client):
    """Ensure empty or whitespace URL returns HTTP 400 Bad Request."""
    for empty_val in ["", "   "]:
        response = client.post(
            "/api/predict",
            data=json.dumps({"url": empty_val}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
        assert "empty" in data["error"].lower()


def test_predict_too_long_url_returns_400(client):
    """Ensure URL > 2048 characters returns HTTP 400 Bad Request."""
    too_long_url = "https://example.com/" + ("x" * 2050)
    response = client.post(
        "/api/predict",
        data=json.dumps({"url": too_long_url}),
        content_type="application/json",
    )
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data
    assert "2048" in data["error"]


def test_predict_invalid_payload_returns_400(client):
    """Ensure missing json or wrong format returns HTTP 400."""
    # Not JSON
    r1 = client.post("/api/predict", data="hello world", content_type="text/plain")
    assert r1.status_code == 400

    # Missing 'url' key
    r2 = client.post("/api/predict", data=json.dumps({"link": "https://test.com"}), content_type="application/json")
    assert r2.status_code == 400


def test_bulk_predict_api(client):
    """Test bulk prediction endpoint with multiple URLs."""
    urls = [
        "https://www.google.com",
        "http://192.168.1.1/login",
        "https://github.com/torvalds/linux",
    ]
    response = client.post(
        "/api/bulk-predict",
        data=json.dumps({"urls": urls}),
        content_type="application/json",
    )
    assert response.status_code == 200
    data = response.get_json()

    assert data["count"] == 3
    assert len(data["results"]) == 3
    assert data["results"][0]["verdict"] == "Legitimate"
    assert data["results"][1]["verdict"] == "Phishing"


def test_feedback_api(client):
    """Test reporting a URL false positive/negative and verifying CSV append."""
    payload = {
        "url": "https://safe-internal-portal.local/login",
        "suggested_label": "legitimate",
        "notes": "Internal company VPN portal test",
    }
    response = client.post(
        "/api/feedback",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "recorded_at" in data

    # Verify that feedback.csv contains the record
    assert os.path.exists(FEEDBACK_PATH)
    with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
        content = f.read()
    assert "safe-internal-portal.local/login" in content
    assert "legitimate" in content


def test_model_info_api(client):
    """Test GET /api/model-info endpoint."""
    response = client.get("/api/model-info")
    assert response.status_code == 200
    data = response.get_json()

    assert "model_name" in data
    assert "feature_names" in data
    assert "feature_importances" in data
    assert "metrics" in data
    assert len(data["feature_names"]) == 15
