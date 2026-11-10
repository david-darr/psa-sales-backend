"""Cached, non-authenticating checks from the actual deployed process.

No employee data, credentials, arbitrary hosts or message submission. Public
health metadata only, with one bounded check per process per fifteen minutes.
"""
import smtplib
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from flask import jsonify


def _smtp():
    with smtplib.SMTP('smtp.gmail.com', 587, timeout=3) as connection:
        connection.ehlo()
        connection.starttls(context=ssl.create_default_context())


def _tls(host, port):
    with socket.create_connection((host, port), timeout=3) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname=host):
            pass


def check_fixed_endpoints():
    checks = {
        'gmail_smtp_starttls': _smtp,
        'gmail_imap_tls': lambda: _tls('imap.gmail.com', 993),
        'gmail_https_tls': lambda: _tls('gmail.googleapis.com', 443),
    }
    def run(item):
        name, check = item
        try:
            check()
            return name, True
        except (OSError, smtplib.SMTPException):
            # No socket addresses, provider bodies or exception text in replies.
            return name, False
    with ThreadPoolExecutor(max_workers=3) as executor:
        return dict(executor.map(run, checks.items()))


def register_mail_connectivity(app):
    lock = threading.Lock()
    cached, expires = None, 0

    @app.get('/api/health/mail-connectivity')
    def mail_connectivity():
        nonlocal cached, expires
        if cached is not None and time.monotonic() < expires:
            return jsonify(**cached, queue_worker_mode=app.config.get('OUTREACH_WORKER_MODE','legacy'))
        if not lock.acquire(blocking=False):
            return jsonify(status='checking'), 202
        try:
            if cached is None or time.monotonic() >= expires:
                cached = dict(status='checked', checks=check_fixed_endpoints(),
                    checked_at=datetime.now(timezone.utc).isoformat(),
                    note='Connectivity only; no mailbox login or email send was attempted.')
                expires = time.monotonic() + 900
            return jsonify(**cached, queue_worker_mode=app.config.get('OUTREACH_WORKER_MODE','legacy'))
        finally:
            lock.release()
