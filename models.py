from app import app
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
  __tablename__ = "user"
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(50), nullable=False)
  username = db.Column(db.String(50), nullable=False, unique=True)
  password_hash = db.Column(db.String(256), nullable=False)
  user_type = db.Column(db.Enum('influencer', 'sponsor', 'admin'), nullable=False)
  flagged = db.Column(db.Boolean, nullable=False, default=False)
  theme = db.Column(db.Enum('light', 'dark'), nullable=False, default='light')

  # Influencer specific attributes
  category = db.Column(db.String(50), nullable=True)
  niche = db.Column(db.String(50), nullable=True)
  follower_count = db.Column(db.Integer, nullable=True)
  platforms = db.Column(db.String(150), nullable=True)

  # Sponsor specific attributes
  industry = db.Column(db.String(50), nullable=True)
  budget = db.Column(db.Integer, nullable=True)

class Campaign(db.Model):
  __tablename__ = "campaign"
  id = db.Column(db.Integer, primary_key=True)
  sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  name = db.Column(db.String(50), nullable=False)
  description = db.Column(db.String(256), nullable=False)
  start_date = db.Column(db.DateTime, nullable=False)
  end_date = db.Column(db.DateTime, nullable=False)
  progress = db.Column(db.Integer, nullable=False, default=0)
  budget = db.Column(db.Integer, nullable=False)
  visibility = db.Column(db.Enum('public', 'private'), nullable=False)
  goals = db.Column(db.String(256), nullable=False)
  flagged = db.Column(db.Boolean, nullable=False, default=False)

  # relationships
  sponsor = db.relationship('User', backref=db.backref('campaigns', lazy=True))
  ad_requests = db.relationship('Ad_Request', backref='campaign', cascade='all, delete-orphan')

class Ad_Request(db.Model):
  __tablename__ = "ad_request"
  id = db.Column(db.Integer, primary_key=True)
  campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
  influencer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
  messages = db.Column(db.String(256), nullable=False)
  requirements = db.Column(db.String(256), nullable=False)
  payment_amount = db.Column(db.Integer, nullable=False)
  completed = db.Column(db.Boolean, nullable=False, default=False)
  requested_by = db.Column(db.Enum('influencer', 'sponsor'), nullable=False)
  status = db.Column(db.Enum('pending', 'accepted', 'rejected'), nullable=False, default='pending')

  # relationships
  influencer = db.relationship('User', foreign_keys=[influencer_id], backref=db.backref('ad_requests', lazy=True))

with app.app_context():
  db.create_all()

  admin = User.query.filter_by(user_type="admin").first()
  if not admin:
    admin = User(name="Admin", username="admin", password_hash=generate_password_hash("admin"), user_type="admin")
    db.session.add(admin)
    db.session.commit()