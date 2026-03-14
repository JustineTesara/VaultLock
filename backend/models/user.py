# backend/models/user.py
# Represents the "users" table in PostgreSQL

from extensions import db, bcrypt
from flask_login import UserMixin
from datetime import datetime



class User(UserMixin, db.Model):
    """
    UserMixin gives us these free methods from Flask-Login:
    - is_authenticated  → True if the user is logged in
    - is_active         → True (we can override for banning users)
    - get_id()          → returns the user's id as a string
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    
    # We NEVER store the real master password — only its bcrypt hash
    hashed_master_password = db.Column(db.String(255), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Track failed login attempts for brute-force protection
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    # One user has many stored passwords (one-to-many relationship)
    # cascade="all, delete-orphan" means: delete all passwords when a user is deleted
    passwords = db.relationship(
        'StoredPassword',
        backref='owner',
        lazy=True,
        cascade="all, delete-orphan"
    )

    def set_password(self, plain_password: str):
        """
        Hash the master password with bcrypt and save the hash.
        
        bcrypt automatically:
        - Adds a random salt (prevents rainbow table attacks)
        - Applies many rounds of hashing (slow by design — stops brute force)
        - Encodes the salt INTO the hash (no need to store salt separately)
        """
        self.hashed_master_password = bcrypt.generate_password_hash(
            plain_password,
            rounds=12   # Work factor: higher = slower but more secure
        ).decode('utf-8')

    def check_password(self, plain_password: str) -> bool:
        """
        Compare a plain password against the stored bcrypt hash.
        Returns True if they match, False otherwise.
        """
        return bcrypt.check_password_hash(
            self.hashed_master_password,
            plain_password
        )

    def is_locked(self) -> bool:
        """Check if the account is currently locked due to too many failed logins."""
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False

    def __repr__(self):
        return f'<User {self.email}>'