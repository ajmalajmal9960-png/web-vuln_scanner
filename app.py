"""
app.py
Flask API server. Serves the frontend dashboard and exposes scan endpoints.

Run with:  python app.py
Then open: http://127.0.0.1:5000
"""

from flask import Flask, request, jsonify, send_from_directory
import requests as _requests_lib

import scanner
import demo_data
import database

app = Flask(__name__, static_folder="../frontend", static_url_path="")

database.init_db()


# Manual CORS headers (no flask-cors dependency needed - one less thing that
# can fail to install). Only matters if you ever serve the frontend from a
# different origin than the API; harmless otherwise.
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target_url = (data.get("url") or "").strip()
    crawl = data.get("crawl", True)

    if not target_url:
        return jsonify({"error": "URL is required"}), 400
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    try:
        results = scanner.run_full_scan(target_url, crawl=crawl)
        scan_id = database.save_scan(target_url, results, mode="live")
        return jsonify({"scan_id": scan_id, "url": target_url, "results": results})
    except _requests_lib.exceptions.ConnectionError:
        return jsonify({"error": f"Could not connect to {target_url}. Check the URL and "
                                   f"that the target is reachable and running."}), 502
    except _requests_lib.exceptions.Timeout:
        return jsonify({"error": f"The request to {target_url} timed out."}), 504
    except Exception as exc:  # noqa: BLE001 - surface any other scan failure to the UI
        return jsonify({"error": f"Scan failed: {exc}"}), 500


@app.route("/api/demo-scan", methods=["POST"])
def demo_scan():
    """
    Offline preview mode: runs the real detection engine against a fixed,
    simulated dataset (modeled on WebGoat/NodeGoat) so you can see exactly
    what a full report looks like without needing a live target or network.
    """
    try:
        results = demo_data.run_demo_scan()
        scan_id = database.save_scan(demo_data.DEMO_TARGET_LABEL, results, mode="demo")
        return jsonify({"scan_id": scan_id, "url": demo_data.DEMO_TARGET_LABEL, "results": results})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Demo scan failed: {exc}"}), 500


@app.route("/api/history", methods=["GET"])
def history():
    return jsonify(database.get_all_scans())


@app.route("/api/history/<int:scan_id>", methods=["GET"])
def history_detail(scan_id):
    scan_record = database.get_scan(scan_id)
    if not scan_record:
        return jsonify({"error": "Not found"}), 404
    return jsonify(scan_record)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
