# backend/routes/auth.py
# Handles registration, login, and logout

from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
from extensions import db, bcrypt, limiter
from models.user import User
from utils.helpers import sanitize_text, sanitize_email

auth_bp = Blueprint('auth', __name__)


# ─── REGISTER ─────────────────────────────────────────────────────────────────

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    # If already logged in, go straight to vault
    if current_user.is_authenticated:
        return redirect(url_for('vault.vault_home'))

    if request.method == 'POST':
        email    = sanitize_email(request.form.get('email', ''))
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        if not email:
            flash('Please enter a valid email address.', 'error')
            return render_template('register.html')

        # ── Validation ──────────────────────────────────────────────────────
        if not email or not password or not confirm:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Master password must be at least 8 characters.', 'error')
            return render_template('register.html')

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')

        # ── Check for duplicate email ────────────────────────────────────────
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            # Intentionally vague — don't reveal if email exists
            flash('An account with that email already exists.', 'error')
            return render_template('register.html')

        # ── Create user — password is hashed inside set_password() ──────────
        new_user = User(email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Account created! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


# ─── LOGIN ────────────────────────────────────────────────────────────────────

@auth_bp.route('/', methods=['GET', 'POST'])
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")   # Max 10 login attempts per minute per IP
def login():
    if current_user.is_authenticated:
        return redirect(url_for('vault.vault_home'))

    if request.method == 'POST':
        email    = sanitize_email(request.form.get('email', ''))
        password = request.form.get('password', '')

        if not email or not password:
            flash('Both fields are required.', 'error')
            return render_template('login.html')

        user = User.query.filter_by(email=email).first()

        # ── Account lockout check ────────────────────────────────────────────
        # We check BEFORE verifying the password to save time
        if user and user.is_locked():
            remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
            flash(f'Account locked. Try again in {remaining} minute(s).', 'error')
            return render_template('login.html')

        # ── Verify password ──────────────────────────────────────────────────
        if user and user.check_password(password):
            # Success — reset failed attempts and start session
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()

            # remember=False means session ends when browser closes
            login_user(user, remember=False)

            # Make session expire after inactivity (from config)
            session.permanent = True

            flash('Welcome back!', 'success')

            # Redirect to the page they were trying to visit, or vault
            next_page = request.args.get('next')
            return redirect(next_page or url_for('vault.vault_home'))

        else:
            # Failed login — increment counter
            if user:
                user.failed_login_attempts += 1

                # Lock after 5 failed attempts for 5 minutes
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=5)
                    db.session.commit()
                    flash('Too many failed attempts. Account locked for 5 minutes.', 'error')
                    return render_template('login.html')

                db.session.commit()

            # Generic message — never reveal whether email exists
            flash('Invalid email or password.', 'error')

    return render_template('login.html')


# ─── LOGOUT ───────────────────────────────────────────────────────────────────

@auth_bp.route('/logout')
@login_required   # Can't logout if not logged in
def logout():
    logout_user()           # Clears Flask-Login session
    session.clear()         # Clears all session data
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.errorhandler(429)
def rate_limit_handler(e):
    flash('Too many attempts. Please wait a moment before trying again.', 'error')
    return render_template('login.html'), 429