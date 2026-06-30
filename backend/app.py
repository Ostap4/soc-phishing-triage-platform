import os
from pathlib import Path
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
from models import db
from routers.scans import scans_bp
from routers.auth import auth_bp


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_MB", "10")) * 1024 * 1024


frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")

CORS(
    app,
    resources={
        r"/*": {
            "origins": [
                frontend_url,
                "http://127.0.0.1:3000",
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            ],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
        }
    },
)


app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY") or os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


db.init_app(app)

with app.app_context():
    db.create_all()
    print("[*] PostgreSQL tables ('users' and 'scans') checked/created successfully!")


app.register_blueprint(scans_bp)
app.register_blueprint(auth_bp, url_prefix="/auth")


@app.route("/")
def home():
    return "SOC Phishing Triage Web-Server is Running!"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
