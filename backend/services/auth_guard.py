import jwt
from functools import wraps
from flask import request, jsonify, current_app


def get_current_user_id():
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.replace("Bearer ", "", 1).strip()

    try:
        payload = jwt.decode(
            token,
            current_app.config["SECRET_KEY"],
            algorithms=["HS256"]
        )

        return payload.get("user_id")

    except jwt.ExpiredSignatureError:
        return None

    except jwt.InvalidTokenError:
        return None


def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user_id = get_current_user_id()

        if not user_id:
            return jsonify({"error": "Unauthorized or expired token"}), 401

        return fn(user_id, *args, **kwargs)

    return wrapper