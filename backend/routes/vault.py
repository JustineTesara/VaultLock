# backend/routes/vault.py

from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from models.password import StoredPassword
from utils.encryption import decrypt_password


vault_bp = Blueprint('vault', __name__)


@vault_bp.route('/vault')
@login_required
def vault_home():
    # Fetch only THIS user's passwords — never another user's
    passwords = StoredPassword.query.filter_by(
        user_id=current_user.id
    ).order_by(StoredPassword.created_at.desc()).all()

    return render_template('vault.html', passwords=passwords)



vault_bp = Blueprint('vault', __name__)


@vault_bp.route('/vault')
@login_required
def vault_home():
    passwords = StoredPassword.query.filter_by(
        user_id=current_user.id
    ).order_by(StoredPassword.created_at.desc()).all()
    return render_template('vault.html', passwords=passwords)


@vault_bp.route('/vault/get-password/<int:entry_id>')
@login_required
def get_password(entry_id):
    # SECURITY: always filter by user_id too — prevents user A
    # from fetching user B's password by guessing the ID
    entry = StoredPassword.query.filter_by(
        id=entry_id,
        user_id=current_user.id
    ).first()

    if not entry:
        return jsonify({'error': 'Not found'}), 404

    return jsonify({'password': decrypt_password(entry.encrypted_password)})