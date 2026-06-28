from models import db
from datetime import datetime

class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    #Foreign Key
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    
    filename = db.Column(db.String(255), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending') # Pending, Completed, Failed
    
    
    vt_malicious_urls = db.Column(db.Integer, default=0)
    vt_malicious_files = db.Column(db.Integer, default=0)
    
    
    ai_report = db.Column(db.JSON, nullable=True) 
    mismatched_links = db.Column(db.JSON, nullable=True) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f'<Scan {self.filename} - Status: {self.status}>'