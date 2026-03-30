# backend/models/password.py
# Represents the "passwords" table — the actual vault entries

from extensions import db
from datetime import datetime


class StoredPassword(db.Model):
    """
    Each row is one saved credential in a user's vault.
    The password field is ALWAYS stored encrypted — never plain text.
    """
    __tablename__ = 'passwords'

    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign key links each entry back to its owner
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id'),
        nullable=False,
        index=True   # Index makes searching by user_id fast
    )

    website_name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(200), nullable=False)
    
    # This field ALWAYS contains the AES-256-GCM encrypted password
    # The plain text password is NEVER stored here
    encrypted_password = db.Column(db.Text, nullable=False)
    
    notes = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=True, default='Other')

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self, include_password=False) -> dict:
        """
        Convert the model to a dictionary for JSON responses.
        
        IMPORTANT: We never send the encrypted password to the frontend.
        Only send the decrypted password when explicitly requested
        (i.e. when user clicks "reveal password").
        """
        data = {
            'id': self.id,
            'website_name': self.website_name,
            'username': self.username,
            'notes': self.notes,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
        }
        
        if include_password:
            from utils.encryption import decrypt_password
            data['password'] = decrypt_password(self.encrypted_password)
        
        return data

    def __repr__(self):
        return f'<StoredPassword {self.website_name} - {self.username}>'