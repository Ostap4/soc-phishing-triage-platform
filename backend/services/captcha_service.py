import os
import requests


def verify_turnstile_token(token, remote_ip=None):
    """
    Verifies Cloudflare Turnstile CAPTCHA token.
    """

    secret_key = os.getenv("TURNSTILE_SECRET_KEY")

    if not secret_key:
        print("[ERROR] TURNSTILE_SECRET_KEY is missing")
        return False

    if not token:
        return False

    payload = {
        "secret": secret_key,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload,
            timeout=5,
        )

        result = response.json()
        return result.get("success", False)

    except Exception as e:
        print(f"[ERROR] CAPTCHA verification failed: {e}")
        return False
