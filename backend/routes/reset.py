# backend/routes/reset.py
# Handles forgot-password and reset-password flow

from flask import (
    Blueprint, render_template, redirect,
    url_for, request, flash
)
from flask_mail import Message
from datetime import datetime, timedelta
import secrets

from extensions import db, mail
from models.user import User

reset_bp = Blueprint('reset', __name__)


# ─── STEP 1: User requests a reset link ───────────────────

@reset_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user  = User.query.filter_by(email=email).first()

        # SECURITY: Always show the same message whether the
        # email exists or not — prevents email enumeration attacks.
        # (An attacker shouldn't be able to discover which emails
        #  are registered by trying the forgot password form.)
        if user:
            # Generate a secure random 32-byte token
            token = secrets.token_urlsafe(32)

            # Save token + expiry (valid for 1 hour)
            user.reset_token        = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

            # Build the reset link
            reset_link = url_for('reset.reset_password',
                                 token=token, _external=True)

            # Send the email
            try:
                msg = Message(
                    subject='CipherNest — Reset your master password',
                    recipients=[user.email]
                )
                msg.body = f"""Hello,

You requested a password reset for your CipherNest account.

Click the link below to reset your master password.
This link expires in 1 hour.

{reset_link}

If you did not request this, you can safely ignore this email.
Your account has not been changed.

— The CipherNest Team
"""
                mail.send(msg)
            except Exception as e:
                print(f'Mail error: {type(e).__name__}: {e}')   # ← shows full error
                flash('Could not send email. Please check your mail config.', 'error')
                return render_template('forgot.html')

        flash('If that email is registered, a reset link has been sent.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('forgot.html')


# ─── STEP 2: User clicks the link and sets new password ───

@reset_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Look up the user with this token
    user = User.query.filter_by(reset_token=token).first()

    # Validate: token must exist and not be expired
    if not user or not user.reset_token_expiry \
            or user.reset_token_expiry < datetime.utcnow():
        flash('This reset link is invalid or has expired.', 'error')
        return redirect(url_for('reset.forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password', '')
        confirm      = request.form.get('confirm_password', '')

        if len(new_password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('reset.html', token=token)

        if new_password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset.html', token=token)

        # Set the new password and clear the token
        user.set_password(new_password)
        user.reset_token        = None
        user.reset_token_expiry = None
        db.session.commit()

        flash('Password reset! Please log in with your new master password.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset.html', token=token)