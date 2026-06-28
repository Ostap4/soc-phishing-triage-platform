import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)


from flask import Flask
from flask_cors import CORS


from models import db


from routers.scans import scans_bp
from routers.auth import auth_bp

app = Flask(__name__)


CORS(app)


app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY') or os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)

with app.app_context():
    db.create_all()
    print("[*] PostgreSQL tables ('users' and 'scans') checked/created successfully!")


app.register_blueprint(scans_bp)
app.register_blueprint(auth_bp, url_prefix = '/auth')

@app.route('/')
def home():
    return "SOC Phishing Triage Web-Server is Running!"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)