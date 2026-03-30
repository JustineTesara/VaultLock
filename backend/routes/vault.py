# backend/routes/vault.py

from flask import Blueprint, render_template, jsonify, request, redirect, url_for
from flask_login import login_required, current_user
from extensions import db
from models.password import StoredPassword
from utils.encryption import encrypt_password, decrypt_password
from utils.helpers import sanitize_text

vault_bp = Blueprint('vault', __name__)


# ─── VAULT HOME ───────────────────────────────────────────────────────────────

@vault_bp.route('/vault')
@login_required
def vault_home():
    passwords = StoredPassword.query.filter_by(
        user_id=current_user.id
    ).order_by(StoredPassword.created_at.desc()).all()
    return render_template('vault.html', passwords=passwords)


# ─── GET DECRYPTED PASSWORD (for copy button) ─────────────────────────────────

@vault_bp.route('/vault/get-password/<int:entry_id>')
@login_required
def get_password(entry_id):
    # Always filter by user_id — prevents accessing another user's data
    entry = StoredPassword.query.filter_by(
        id=entry_id,
        user_id=current_user.id
    ).first()

    if not entry:
        return jsonify({'error': 'Not found'}), 404

    return jsonify({'password': decrypt_password(entry.encrypted_password)})


# ─── ADD PASSWORD ─────────────────────────────────────────────────────────────

@vault_bp.route('/vault/add', methods=['POST'])
@login_required
def add_password():
    website  = sanitize_text(request.form.get('website_name', ''), max_length=200)
    username = sanitize_text(request.form.get('username', ''), max_length=200)
    password = request.form.get('password', '')
    notes    = sanitize_text(request.form.get('notes', ''), max_length=500) 
    category = request.form.get('category', 'Other')

    # Validate required fields
    if not website or not username or not password:
        return jsonify({'error': 'Website, username, and password are required.'}), 400

    # Encrypt before saving — plain text never touches the database
    encrypted = encrypt_password(password)

    entry = StoredPassword(
        user_id=current_user.id,
        website_name=website,
        username=username,
        encrypted_password=encrypted,
        notes=notes or None,
        category=category,
    )

    db.session.add(entry)
    db.session.commit()

    return jsonify({
        'success': True,
        'entry': {
            'id':           entry.id,
            'website_name': entry.website_name,
            'username':     entry.username,
            'notes':        entry.notes or '',
            'category':     entry.category,
            'created_at':   entry.created_at.strftime('%Y-%m-%d %H:%M'),
        }
    })


# ─── EDIT PASSWORD ────────────────────────────────────────────────────────────

@vault_bp.route('/vault/edit/<int:entry_id>', methods=['POST'])
@login_required
def edit_password(entry_id):
    # Ownership check — critical security gate
    entry = StoredPassword.query.filter_by(
        id=entry_id,
        user_id=current_user.id
    ).first()

    if not entry:
        return jsonify({'error': 'Not found'}), 404

    website  = sanitize_text(request.form.get('website_name', ''), max_length=200)
    username = sanitize_text(request.form.get('username', ''), max_length=200)
    password = request.form.get('password', '')
    notes    = sanitize_text(request.form.get('notes', ''), max_length=500)
    category = request.form.get('category', 'Other')


    if not website or not username:
        return jsonify({'error': 'Website and username are required.'}), 400

    entry.website_name = website
    entry.username     = username
    entry.notes        = notes or None
    entry.category = category

    # Only re-encrypt if the user typed a new password
    # If the field is blank we keep the existing encrypted value
    if password:
        entry.encrypted_password = encrypt_password(password)

    db.session.commit()

    return jsonify({'success': True, 'website_name': entry.website_name})


# ─── DELETE PASSWORD ──────────────────────────────────────────────────────────

@vault_bp.route('/vault/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_password(entry_id):
    entry = StoredPassword.query.filter_by(
        id=entry_id,
        user_id=current_user.id
    ).first()

    if not entry:
        return jsonify({'error': 'Not found'}), 404

    db.session.delete(entry)
    db.session.commit()

    return jsonify({'success': True})