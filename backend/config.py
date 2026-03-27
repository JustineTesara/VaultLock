import os
from dotenv import load_dotenv

load_dotenv()  # Load .env file into environment variables

class Config:
    APP_NAME = 'CipherNest'              # Application name
    APP_TAGLINE = 'Secure Password Manager'  # Short description for SEO and display purposes
    
    # Flask secret key — used to sign session cookies
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'fallback-dev-key-change-in-production'
    
    # PostgreSQL connection string
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Saves memory
    
    # Session security settings
    SESSION_COOKIE_HTTPONLY = True   # JS can't read the cookie
    SESSION_COOKIE_SECURE = False    # Set True in production (HTTPS only)
    SESSION_COOKIE_SAMESITE = 'Lax' # Prevents CSRF via cross-site requests
    
    # Auto-logout after 15 minutes of inactivity
    PERMANENT_SESSION_LIFETIME = 900  # seconds
    
    # Rate limiting storage (in-memory for dev)
    RATELIMIT_STORAGE_URL = "memory://"