import os
import jwt
import datetime

from flask import Blueprint, request, jsonify, current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

from services.password_policy import validate_password_strength

from models import db
from models.user import User

from models.login_attempt import LoginAttempt
from services.captcha_service import verify_turnstile_token
from services.email_service import send_reset_email

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


MAX_FAILED_LOGIN_ATTEMPTS = 3
LOGIN_LOCK_MINUTES = 7


def get_client_ip():
    trust_proxy = os.getenv("TRUST_PROXY", "false").lower() == "true"

    if trust_proxy:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "unknown"


def get_or_create_login_attempt(email, ip_address):
    attempt = LoginAttempt.query.filter_by(email=email, ip_address=ip_address).first()

    if not attempt:
        attempt = LoginAttempt(email=email, ip_address=ip_address, failed_count=0)
        db.session.add(attempt)
        db.session.commit()

    return attempt


def register_failed_login(email, ip_address):
    now = datetime.datetime.utcnow()

    attempt = get_or_create_login_attempt(email, ip_address)

    if attempt.locked_until and now >= attempt.locked_until:
        attempt.failed_count = 0
        attempt.locked_until = None
        attempt.first_failed_at = None

    attempt.failed_count += 1
    attempt.last_failed_at = now

    if not attempt.first_failed_at:
        attempt.first_failed_at = now

    if attempt.failed_count >= MAX_FAILED_LOGIN_ATTEMPTS:
        attempt.locked_until = now + datetime.timedelta(minutes=LOGIN_LOCK_MINUTES)

    db.session.commit()
    return attempt


def reset_login_attempts(email, ip_address):
    attempt = LoginAttempt.query.filter_by(email=email, ip_address=ip_address).first()

    if attempt:
        attempt.failed_count = 0
        attempt.first_failed_at = None
        attempt.last_failed_at = None
        attempt.locked_until = None
        db.session.commit()


@auth_bp.route("/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200

    data = request.get_json(silent=True) or {}

    email = data.get("email")
    password = data.get("password")
    captcha_token = data.get("captchaToken")
    ip_address = get_client_ip()

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    if not verify_turnstile_token(captcha_token, ip_address):
        return jsonify({"error": "CAPTCHA verification failed."}), 400

    password_errors = validate_password_strength(password)
    if password_errors:
        return (
            jsonify(
                {
                    "error": "Password does not meet security requirements.",
                    "details": password_errors,
                }
            ),
            400,
        )

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "Email already registered."}), 400

    new_user = User(email=email)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()

        return (
            jsonify(
                {
                    "message": "User registered successfully.",
                    "email": new_user.email,
                    "id": new_user.id,
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Registration database error: {e}")

        return jsonify({"error": "Database error occurred."}), 500


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    password = data.get("password")
    captcha_token = data.get("captchaToken")

    ip_address = get_client_ip()

    if not email or not password:
        return jsonify({"detail": "Email and password are required"}), 400

    attempt = get_or_create_login_attempt(email, ip_address)

    if attempt.is_locked():
        return (
            jsonify(
                {
                    "detail": "Too many failed login attempts. Please try again later.",
                    "locked": True,
                    "retry_after_seconds": attempt.seconds_until_unlock(),
                    "captcha_required": True,
                }
            ),
            423,
        )

    captcha_required = attempt.failed_count >= MAX_FAILED_LOGIN_ATTEMPTS

    if captcha_required:
        if not verify_turnstile_token(captcha_token, ip_address):
            return (
                jsonify(
                    {
                        "detail": "CAPTCHA verification required",
                        "captcha_required": True,
                    }
                ),
                400,
            )

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        attempt = register_failed_login(email, ip_address)

        return (
            jsonify(
                {
                    "detail": "Invalid credentials",
                    "failed_count": attempt.failed_count,
                    "captcha_required": attempt.failed_count
                    >= MAX_FAILED_LOGIN_ATTEMPTS,
                    "locked": attempt.is_locked(),
                    "retry_after_seconds": attempt.seconds_until_unlock(),
                }
            ),
            401,
        )

    reset_login_attempts(email, ip_address)

    token_payload = {
        "user_id": user.id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
    }

    token = jwt.encode(
        token_payload, current_app.config["SECRET_KEY"], algorithm="HS256"
    )

    return (
        jsonify(
            {
                "access_token": token,
                "token_type": "bearer",
                "user_id": user.id,
                "email": user.email,
            }
        ),
        200,
    )


@auth_bp.route("/forgot-password", methods=["POST", "OPTIONS"])
def forgot_password():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200

    data = request.get_json(silent=True) or {}
    email = data.get("email")
    captcha_token = data.get("captchaToken")
    ip_address = get_client_ip()

    if not verify_turnstile_token(captcha_token, ip_address):
        return jsonify({"message": "CAPTCHA verification failed"}), 400

    if not email:
        return (
            jsonify(
                {"message": "If the email is registered, a reset link will be sent."}
            ),
            200,
        )

    user = User.query.filter_by(email=email).first()

    if user:
        serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        token = serializer.dumps(email, salt="password-reset-salt")

        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        reset_link = f"{frontend_url}/reset-password?token={token}"

        send_reset_email(email, reset_link)

        print(f"[SECURITY EVENT] Password reset token dispatched via SMTP to: {email}")

    return (
        jsonify({"message": "If the email is registered, a reset link will be sent."}),
        200,
    )


@auth_bp.route("/reset-password", methods=["POST", "OPTIONS"])
def reset_password():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200

    data = request.get_json(silent=True) or {}

    token = data.get("token")
    new_password = data.get("password")
    captcha_token = data.get("captchaToken")
    ip_address = get_client_ip()

    if not token or not new_password:
        return jsonify({"error": "Missing token or password."}), 400

    if not verify_turnstile_token(captcha_token, ip_address):
        return jsonify({"error": "CAPTCHA verification failed."}), 400

    password_errors = validate_password_strength(new_password)
    if password_errors:
        return (
            jsonify(
                {
                    "error": "Password does not meet security requirements.",
                    "details": password_errors,
                }
            ),
            400,
        )

    try:
        serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])

        email = serializer.loads(token, salt="password-reset-salt", max_age=900)

    except SignatureExpired:
        return (
            jsonify({"error": "The reset link has expired. Please request a new one."}),
            400,
        )

    except BadTimeSignature:
        return jsonify({"error": "Invalid reset link."}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "User not found."}), 404

    user.set_password(new_password)

    try:
        db.session.commit()

        return jsonify({"message": "Password successfully updated."}), 200

    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Password reset database error: {e}")

        return jsonify({"error": "Database error occurred."}), 500
