# All admin pages and API endpoints live here

from flask import (
    Blueprint, render_template, redirect,
    url_for, request, session, flash, jsonify
)
from functools import wraps
from datetime import datetime, timedelta
import os

from extensions import db
from models.user import User
from models.password import StoredPassword

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# ─── ADMIN AUTH GUARD ─────────────────────────────────────────────────────────
# This is a decorator — we put @admin_required above any route that
# should only be accessible to a logged-in admin.
# If the admin session is not set, redirect to the admin login page.

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please log in to access the admin panel.', 'warning')
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated


# ─── ADMIN LOGIN ──────────────────────────────────────────────────────────────

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, go straight to dashboard
    if session.get('admin_logged_in'):
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        admin_email = os.environ.get('ADMIN_EMAIL', '').lower()
        admin_pass  = os.environ.get('ADMIN_PASSWORD', '')

        if email == admin_email and password == admin_pass:
            # Set admin session flag
            session['admin_logged_in'] = True
            session['admin_email']     = email
            session.permanent          = True
            flash('Welcome to the admin panel.', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid admin credentials.', 'error')

    return render_template('admin/login.html')


# ─── ADMIN LOGOUT ─────────────────────────────────────────────────────────────

@admin_bp.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_email', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin.login'))


# ─── DASHBOARD OVERVIEW ───────────────────────────────────────────────────────

@admin_bp.route('/')
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    # Gather statistics to display on the overview cards
    total_users     = User.query.count()
    total_passwords = StoredPassword.query.count()
    locked_accounts = User.query.filter(
        User.locked_until > datetime.utcnow()
    ).count()

    # Users who joined in the last 7 days
    week_ago      = datetime.utcnow() - timedelta(days=7)
    new_this_week = User.query.filter(User.created_at >= week_ago).count()

    # 10 most recent users for the activity table
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()

    return render_template('admin/dashboard.html',
        total_users     = total_users,
        total_passwords = total_passwords,
        locked_accounts = locked_accounts,
        new_this_week   = new_this_week,
        recent_users    = recent_users,
        now             = datetime.utcnow(),
    )


# ─── USER MANAGEMENT ──────────────────────────────────────────────────────────

@admin_bp.route('/users')
@admin_required
def users():
    search = request.args.get('search', '').strip()

    if search:
        # Filter by email if search query is provided
        all_users = User.query.filter(
            User.email.ilike(f'%{search}%')
        ).order_by(User.created_at.desc()).all()
    else:
        all_users = User.query.order_by(User.created_at.desc()).all()

    # Attach password count to each user
    # We do this here so the template stays clean
    users_data = []
    for u in all_users:
        pwd_count = StoredPassword.query.filter_by(user_id=u.id).count()
        users_data.append({
            'id':                    u.id,
            'email':                 u.email,
            'created_at':            u.created_at,
            'failed_login_attempts': u.failed_login_attempts,
            'is_locked':             u.is_locked(),
            'locked_until':          u.locked_until,
            'password_count':        pwd_count,
        })

    return render_template('admin/users.html',
        users  = users_data,
        search = search,
    )


# ─── LOCK / UNLOCK USER ───────────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/lock', methods=['POST'])
@admin_required
def lock_user(user_id):
    user = User.query.get_or_404(user_id)
    # Lock for 24 hours
    user.locked_until          = datetime.utcnow() + timedelta(hours=24)
    user.failed_login_attempts = 5
    db.session.commit()
    flash(f'{user.email} has been locked for 24 hours.', 'warning')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/unlock', methods=['POST'])
@admin_required
def unlock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.locked_until          = None
    user.failed_login_attempts = 0
    db.session.commit()
    flash(f'{user.email} has been unlocked.', 'success')
    return redirect(url_for('admin.users'))


# ─── DELETE USER ──────────────────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    email = user.email
    # cascade="all, delete-orphan" on the relationship handles
    # deleting all of this user's passwords automatically
    db.session.delete(user)
    db.session.commit()
    flash(f'User {email} and all their data have been deleted.', 'error')
    return redirect(url_for('admin.users'))


# ─── RESET FAILED ATTEMPTS ────────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/reset-attempts', methods=['POST'])
@admin_required
def reset_attempts(user_id):
    user = User.query.get_or_404(user_id)
    user.failed_login_attempts = 0
    user.locked_until          = None
    db.session.commit()
    flash(f'Login attempts reset for {user.email}.', 'success')
    return redirect(url_for('admin.users'))


# ─── STATS API (used by dashboard charts) ────────────────────────────────────

@admin_bp.route('/api/stats')
@admin_required
def stats_api():
    """Returns JSON stats — used by the dashboard for live data."""
    return jsonify({
        'total_users':     User.query.count(),
        'total_passwords': StoredPassword.query.count(),
        'locked_accounts': User.query.filter(
            User.locked_until > datetime.utcnow()
        ).count(),
    })