import datetime
from models import db


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), nullable=False, index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)

    failed_count = db.Column(db.Integer, nullable=False, default=0)

    first_failed_at = db.Column(db.DateTime, nullable=True)
    last_failed_at = db.Column(db.DateTime, nullable=True)

    locked_until = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow
    )

    def is_locked(self):
        if not self.locked_until:
            return False
        return datetime.datetime.utcnow() < self.locked_until

    def seconds_until_unlock(self):
        if not self.locked_until:
            return 0

        remaining = self.locked_until - datetime.datetime.utcnow()
        return max(int(remaining.total_seconds()), 0)