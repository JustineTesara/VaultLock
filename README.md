# 🔐 VaultLock — Secure Password Manager

A full-stack password manager built for learning purposes, inspired by tools like Bitwarden and LastPass. Passwords are encrypted with AES-256-GCM before being stored in the database and are only decrypted on demand when displayed to the authenticated user.

---

## Screenshots

> ![alt text](image.png)
> ![alt text](image-1.png)
> ![alt text](image-2.png)
> ![alt text](image-3.png)
> ![alt text](image-4.png)
> ![alt text](image-5.png)
> ![alt text](image-6.png)
> ![alt text](image-8.png)
> ![alt text](image-7.png)

## Features

- **User authentication** — registration, login, logout with bcrypt-hashed master passwords
- **AES-256-GCM encryption** — every stored password is encrypted before hitting the database
- **Password vault** — add, edit, delete, copy, and search saved credentials
- **Password generator** — cryptographically secure, configurable length and character types
- **Password strength checker** — real-time feedback on register and vault forms
- **Brute force protection** — account locks for 5 minutes after 5 failed login attempts
- **Auto logout** — session expires after 15 minutes of inactivity
- **CSRF protection** — all forms are protected via Flask-WTF
- **Security headers** — CSP, X-Frame-Options, nosniff, and more on every response
- **Dark mode UI** — clean dashboard built with Tailwind CSS

---

## Tech Stack

| Layer      | Technology                                      |
| ---------- | ----------------------------------------------- |
| Frontend   | HTML, Tailwind CSS, Vanilla JavaScript          |
| Backend    | Python 3, Flask                                 |
| Database   | PostgreSQL + SQLAlchemy                         |
| Encryption | Python `cryptography` library (AES-256-GCM)     |
| Auth       | Flask-Login, Flask-Bcrypt                       |
| Security   | Flask-WTF (CSRF), Flask-Limiter (rate limiting) |

---

## Project Structure

```
password-manager/
├── .env                          # secrets — never commit this
├── .gitignore
├── requirements.txt
│
├── backend/
│   ├── app.py                    # Flask app factory
│   ├── config.py                 # configuration from .env
│   ├── extensions.py             # shared Flask extensions
│   │
│   ├── models/
│   │   ├── user.py               # User table + bcrypt helpers
│   │   └── password.py           # StoredPassword table
│   │
│   ├── routes/
│   │   ├── auth.py               # register, login, logout
│   │   └── vault.py              # CRUD + copy endpoint
│   │
│   └── utils/
│       ├── encryption.py         # AES-256-GCM encrypt / decrypt
│       ├── helpers.py            # input sanitization
│       └── security.py           # HTTP security headers
│
└── frontend/
    ├── templates/
    │   ├── base.html             # shared layout + flash messages
    │   ├── login.html            # login page
    │   ├── register.html         # register page
    │   └── vault.html            # vault dashboard
    └── static/
        ├── css/
        └── js/
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- PostgreSQL 14+
- Git

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv

# Mac / Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up PostgreSQL

```sql
-- Run in psql as postgres superuser
CREATE DATABASE password_manager;
CREATE USER vaultuser WITH PASSWORD 'yourStrongPassword';
GRANT ALL PRIVILEGES ON DATABASE password_manager TO vaultuser;

-- PostgreSQL 15+ also needs this
\c password_manager
ALTER SCHEMA public OWNER TO vaultuser;
```

### 5. Generate your encryption key

```bash
python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

Copy the output — you'll need it in the next step.

### 6. Create the `.env` file

Create a file called `.env` in the project root:

```env
SECRET_KEY=your-long-random-secret-key-here
DATABASE_URL=postgresql://vaultuser:yourStrongPassword@localhost/password_manager
ENCRYPTION_KEY=paste-the-generated-key-here
FLASK_ENV=development
```

> ⚠️ Never commit `.env` to version control. It is already in `.gitignore`.

### 7. Run the application

```bash
cd backend
python app.py
```

Visit `http://localhost:5000` in your browser.

---

## How the Encryption Works

Every password goes through this pipeline before being saved:

```
Plain text password
      ↓
Generate 12-byte random nonce (IV)
      ↓
AES-256-GCM encrypt using key from .env
      ↓
base64(nonce + ciphertext + auth tag)
      ↓
Stored in PostgreSQL
```

On retrieval, the process reverses. The authentication tag built into GCM mode means any tampering with the stored data is detected and decryption fails.

The encryption key lives only in `.env` — never in the database. This means even if the database is stolen, the passwords cannot be decrypted without the key.

---

## Security Features

| Feature                 | Details                                         |
| ----------------------- | ----------------------------------------------- |
| Password hashing        | bcrypt with 12 work factor rounds               |
| Vault encryption        | AES-256-GCM, unique nonce per entry             |
| Brute force protection  | 5 failed attempts → 5 minute account lockout    |
| Rate limiting           | Max 10 login requests per minute per IP         |
| CSRF protection         | Token validated on every POST request           |
| Session security        | HttpOnly + SameSite=Lax cookies                 |
| Auto logout             | 15 minutes of inactivity                        |
| XSS protection          | Content-Security-Policy headers + HTML escaping |
| Clickjacking protection | `X-Frame-Options: DENY`                         |
| Input sanitization      | All form fields stripped and HTML-escaped       |
| Ownership isolation     | Every DB query filters by `user_id`             |
| Cache prevention        | `Cache-Control: no-store` on all HTML responses |

---

## API Endpoints

| Method   | Route                      | Description               | Auth required |
| -------- | -------------------------- | ------------------------- | ------------- |
| GET      | `/`                        | Redirect to login         | No            |
| GET/POST | `/register`                | Create account            | No            |
| GET/POST | `/login`                   | Log in                    | No            |
| GET      | `/logout`                  | Log out                   | Yes           |
| GET      | `/vault`                   | Vault dashboard           | Yes           |
| GET      | `/vault/get-password/<id>` | Decrypt + return password | Yes           |
| POST     | `/vault/add`               | Add new credential        | Yes           |
| POST     | `/vault/edit/<id>`         | Edit credential           | Yes           |
| POST     | `/vault/delete/<id>`       | Delete credential         | Yes           |

---

## Database Schema

### users

| Column                 | Type        | Description           |
| ---------------------- | ----------- | --------------------- |
| id                     | Integer PK  | Auto increment        |
| email                  | String(150) | Unique, indexed       |
| hashed_master_password | String(255) | bcrypt hash           |
| failed_login_attempts  | Integer     | Brute force counter   |
| locked_until           | DateTime    | Lockout expiry        |
| created_at             | DateTime    | Account creation time |

### passwords

| Column             | Type        | Description           |
| ------------------ | ----------- | --------------------- |
| id                 | Integer PK  | Auto increment        |
| user_id            | Integer FK  | References users.id   |
| website_name       | String(200) | Site or app name      |
| username           | String(200) | Username or email     |
| encrypted_password | Text        | AES-256-GCM encrypted |
| notes              | Text        | Optional notes        |
| created_at         | DateTime    | Entry creation time   |
| updated_at         | DateTime    | Last modified time    |

---

## Running Tests

Verify the encryption engine works:

```bash
cd backend
python utils/encryption.py
```

Verify the database tables exist:

```bash
python -c "
from app import create_app, db
from sqlalchemy import inspect
app = create_app()
with app.app_context():
    print('Tables:', inspect(db.engine).get_table_names())
"
```

---

## Important Disclaimers

This project was built for **learning purposes**. Before using it to store real passwords:

- Run it over HTTPS only (use a reverse proxy like Nginx with Let's Encrypt)
- Move from in-memory rate limiting to Redis for production
- Set `FLASK_ENV=production` and `SESSION_COOKIE_SECURE=True`
- Use a production WSGI server like Gunicorn instead of Flask's dev server
- Rotate your `ENCRYPTION_KEY` and `SECRET_KEY` regularly
- Consider adding two-factor authentication

---

## License

This project is for educational use. Feel free to fork and build on it.

---

## Acknowledgements

Built step by step as a learning project covering Flask, PostgreSQL, AES-256 encryption, secure session management, and modern frontend design with Tailwind CSS.
