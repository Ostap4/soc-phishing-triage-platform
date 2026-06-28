import os
import tempfile
from werkzeug.utils import secure_filename
from flask import Blueprint, request, jsonify

from models import db
from models.scan import Scan

from core.parser import EMLParser
from services.vt_scanner import VTScanner
from services.ai_analyzer import AIAnalyzer
from services.auth_guard import jwt_required


scans_bp = Blueprint("scans", __name__, url_prefix="/api/scans")

scanner = VTScanner()
ai = AIAnalyzer()

ALLOWED_EXTENSIONS = {"eml"}


def is_allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@scans_bp.route("/upload", methods=["POST"])
@jwt_required
def upload_scan(current_user_id):
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    if not file or file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not is_allowed_file(file.filename):
        return jsonify({"error": "Only .eml files are allowed"}), 400

    safe_filename = secure_filename(file.filename)

    fd, temp_path = tempfile.mkstemp(suffix=".eml")

    try:
        with os.fdopen(fd, "wb") as f:
            file.save(f)

        parser = EMLParser(temp_path)
        parser.extract_headers()
        parser.extract_body()
        parser.extract_urls()
        parser.extract_attachments()

        parsed_results = parser.get_results()

        urls_to_scan = parsed_results.get("urls", [])
        attachments = parsed_results.get("attachments", [])
        body_plain = parsed_results.get("body_plain", "")
        mismatched_links = parsed_results.get("mismatched_links", [])

        malicious_urls_count = 0
        for url in urls_to_scan:
            vt_report = scanner.get_url_report(url)
            if vt_report.get("status") == "Success" and vt_report.get("malicious", 0) > 0:
                malicious_urls_count += 1

        malicious_files_count = 0
        for att in attachments:
            file_hash = att.get("hash_sha256")
            if not file_hash:
                continue

            vt_report = scanner.get_hash_report(file_hash)
            if vt_report.get("status") == "Success" and vt_report.get("malicious", 0) > 0:
                malicious_files_count += 1

        ai_report = None
        if body_plain:
            ai_report = ai.analyze_text(body_plain)

        ai_verdict = "Unknown"
        brief_reason = None

        if isinstance(ai_report, dict):
            ai_verdict = ai_report.get("ai_verdict", "Unknown")
            brief_reason = ai_report.get("brief_reason")

        new_scan = Scan(
            user_id=current_user_id,
            filename=safe_filename,
            status="Completed",
            vt_malicious_urls=malicious_urls_count,
            vt_malicious_files=malicious_files_count,
            ai_report=ai_report,
            mismatched_links=mismatched_links,
        )

        db.session.add(new_scan)
        db.session.commit()

        return jsonify({
            "message": "Scan completed successfully",
            "scan_id": new_scan.id,
            "filename": new_scan.filename,
            "status": new_scan.status,

            "malicious_urls": malicious_urls_count,
            "malicious_files": malicious_files_count,

            "urls_count": len(urls_to_scan),
            "attachments_count": len(attachments),

            "ai_verdict": ai_verdict,
            "brief_reason": brief_reason,
            "ai_report": ai_report,

            "mismatched_links": mismatched_links,
            "created_at": new_scan.created_at.isoformat() if getattr(new_scan, "created_at", None) else None,
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Scan failed: {e}")
        return jsonify({"error": "Scan failed", "details": str(e)}), 500

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@scans_bp.route("/history", methods=["GET"])
@jwt_required
def get_scan_history(current_user_id):
    scans = (
        Scan.query
        .filter_by(user_id=current_user_id)
        .order_by(Scan.created_at.desc())
        .limit(50)
        .all()
    )

    history = []

    for scan in scans:
        ai_report = scan.ai_report if isinstance(scan.ai_report, dict) else {}

        history.append({
            "id": scan.id,
            "filename": scan.filename,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,

            "malicious_urls": scan.vt_malicious_urls or 0,
            "malicious_files": scan.vt_malicious_files or 0,

            "ai_verdict": ai_report.get("ai_verdict", "Unknown"),
            "brief_reason": ai_report.get("brief_reason"),
            "urgency_level": ai_report.get("urgency_level"),
            "financial_pressure": ai_report.get("financial_pressure"),
        })

    return jsonify({"history": history}), 200


@scans_bp.route("/<int:scan_id>", methods=["GET"])
@jwt_required
def get_scan_details(current_user_id, scan_id):
    scan = Scan.query.filter_by(
        id=scan_id,
        user_id=current_user_id
    ).first()

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    ai_report = scan.ai_report if isinstance(scan.ai_report, dict) else {}

    return jsonify({
        "id": scan.id,
        "filename": scan.filename,
        "status": scan.status,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,

        "malicious_urls": scan.vt_malicious_urls or 0,
        "malicious_files": scan.vt_malicious_files or 0,

        "ai_report": ai_report,
        "mismatched_links": scan.mismatched_links or [],
    }), 200