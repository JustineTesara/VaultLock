# backend/utils/helpers.py
# Input sanitization utilities

import re
import html


def sanitize_text(value: str, max_length: int = 200) -> str:
    """
    Clean user-supplied text before saving to the database.

    Steps:
    1. Strip leading/trailing whitespace
    2. Escape HTML special characters  (<, >, &, ", ')
       This prevents stored XSS if content is ever rendered as HTML
    3. Enforce a maximum length
    4. Remove control characters (null bytes, etc.)
    """
    if not value:
        return ''

    # Strip whitespace
    value = value.strip()

    # Remove control characters (ASCII 0–31 except tab/newline)
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    # Escape HTML entities
    value = html.escape(value, quote=True)

    # Enforce max length
    return value[:max_length]


def sanitize_email(email: str) -> str:
    """Normalize and basic-validate an email address."""
    email = email.strip().lower()
    # Simple format check — not exhaustive but catches obvious bad input
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return ''
    return email[:150]