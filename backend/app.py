# backend/app.py

from flask import Flask
from extensions import db, bcrypt, login_manager, csrf, limiter
from config import Config
from utils.security import apply_security_headers


def create_app():
    app = Flask(
        __name__,
        template_folder='../frontend/templates',
        static_folder='../frontend/static'
    )

    app.config.from_object(Config)

    # Attach all extensions to this app instance
    db.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access the vault.'
    login_manager.login_message_category = 'warning'

    apply_security_headers(app)

    with app.app_context():
        from models.user import User
        from models.password import StoredPassword

        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))

        db.create_all()

        from routes.auth import auth_bp
        from routes.vault import vault_bp
        app.register_blueprint(auth_bp)
        app.register_blueprint(vault_bp)

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)