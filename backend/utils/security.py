# backend/utils/security.py
# Adds HTTP security headers to every response

from flask import Flask


def apply_security_headers(app: Flask):
    """
    Register an after_request hook that injects security headers
    into every single response the app sends.

    Think of these as instructions we send to the browser:
    'Here's what you're allowed to do with this page.'
    """

    @app.after_request
    def add_security_headers(response):

        # ── Content Security Policy ──────────────────────────────
        # Tells the browser EXACTLY which sources are allowed to
        # load scripts, styles, images etc.
        # This is the #1 defense against XSS attacks.
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        # ── Clickjacking protection ──────────────────────────────
        # Prevents your app from being embedded in an iframe on
        # another site (used in clickjacking attacks)
        response.headers['X-Frame-Options'] = 'DENY'

        # ── MIME type sniffing protection ────────────────────────
        # Stops the browser from guessing file types.
        # Without this, an attacker could upload a .jpg that's
        # actually JavaScript and the browser might run it.
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # ── XSS Filter (legacy browsers) ────────────────────────
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # ── Referrer Policy ──────────────────────────────────────
        # Controls how much info is sent in the Referer header
        # when navigating away from your site
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # ── Permissions Policy ───────────────────────────────────
        # Disables browser features your app doesn't need
        # Prevents a compromised page from accessing camera/mic etc.
        response.headers['Permissions-Policy'] = (
            'camera=(), microphone=(), geolocation=(), '
            'payment=(), usb=(), magnetometer=()'
        )

        # ── Cache control for sensitive pages ────────────────────
        # Prevents the browser from caching vault pages.
        # Important: if someone uses a shared computer, the next
        # user shouldn't be able to hit Back and see the vault.
        if '/vault' in response.headers.get('Content-Location', '') \
                or 'text/html' in response.content_type:
            response.headers['Cache-Control'] = (
                'no-store, no-cache, must-revalidate, max-age=0'
            )
            response.headers['Pragma'] = 'no-cache'

        return response

    return app