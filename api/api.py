# ====================================================
# IMPORTS & EXTERNAL LIBRARIES
# ====================================================

import os
import requests
import re
import json
import time
import html
import imaplib
import email
import ssl
import socket
import base64
import threading
import pytz
import atexit
import logging
import hashlib
import secrets
from itsdangerous import URLSafeTimedSerializer, BadSignature
from math import radians, cos, sin, sqrt, atan2, isfinite
from datetime import datetime, timedelta, timezone
import traceback
import gspread
import csv
from io import StringIO

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import email.utils
from email.parser import BytesParser
from email import policy
import smtplib

# Flask & Extensions
from flask import Flask, request, jsonify
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_, and_
from sqlalchemy.orm import joinedload
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)

# Third-party Services
from oauth2client.service_account import ServiceAccountCredentials
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv

# Security & Scheduling
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor

# ====================================================
# ENVIRONMENT & CONFIGURATION
# ====================================================

load_dotenv()
from .mail_credentials import (  # noqa: E402 - dotenv must load before key validation
    MailCredentialUnavailable,
    decrypt_password,
    encrypt_password,
    is_encrypted,
    legacy_reads_enabled,
)
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# ====================================================
# FLASK APP INITIALIZATION
# ====================================================

app = Flask(__name__)

# CORS Configuration
CORS(app, 
     supports_credentials=True, 
     origins=[
         "https://psasales-6l22ucils-david-darrs-projects.vercel.app",
         "https://www.salespsa.com",
         "https://salespsa.com",
         "https://psa-sales-backend.onrender.com",
         "http://localhost:3000",
         "http://localhost:5173"
     ],
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
)

# Database Configuration
database_url = os.getenv("DATABASE_URL")
if not database_url:
    raise RuntimeError("DATABASE_URL is required")
# SQLAlchemy 2.1 defaults to psycopg; this app installs psycopg2-binary.
for prefix in ("postgres://", "postgresql://", "postgresql+psycopg://"):
    if database_url.startswith(prefix):
        database_url = "postgresql+psycopg2://" + database_url[len(prefix):]
        break
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
# Hosted Postgres drops idle connections; test before reuse instead of failing a request.
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True, 'pool_recycle': 280}
db = SQLAlchemy(app)


@app.errorhandler(MailCredentialUnavailable)
def mail_credential_unavailable(_error):
    return jsonify({"error": "Email connection unavailable. Contact your PSA administrator."}), 503

# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
# Default is 15 minutes, which is too easy to hit mid-task (composing a batch email, etc.)
# for an internal sales tool with no refresh-token flow to renew it silently.
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)
jwt = JWTManager(app)

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")
mail = Mail(app)

# ====================================================
# DATABASE MODELS
# ====================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    phone = db.Column(db.String, nullable=True)
    password_hash = db.Column(db.String, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    
    # Email settings for sending emails
    email_password = db.Column(db.String, nullable=True)  # Encrypted Gmail app password
    smtp_server = db.Column(db.String, default='smtp.gmail.com')
    smtp_port = db.Column(db.Integer, default=587)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class EmployeeInvitation(db.Model):
    __tablename__ = 'employee_invitations'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: utc_now())
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)

def utc_now():
    """UTC timestamp stored without timezone, matching the existing database columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

def admin_access_error():
    user = db.session.get(User, int(get_jwt_identity()))
    if not user or not user.admin:
        return jsonify({"error": "Administrator access required"}), 403
    return None

class School(db.Model):
    __tablename__ = 'schools'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    address = db.Column(db.String, nullable=False)
    phone = db.Column(db.String, nullable=False)
    contact = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)

class SalesSchool(db.Model):
    __tablename__ = 'sales_schools'
    id = db.Column(db.Integer, primary_key=True)
    school_name = db.Column(db.String, nullable=False)
    contact_name = db.Column(db.String, nullable=True)
    email = db.Column(db.String, nullable=False)  # Keep primary email
    additional_emails = db.Column(db.Text, nullable=True)  # Store as JSON string
    phone = db.Column(db.String, nullable=True)
    address = db.Column(db.String, nullable=True)
    school_type = db.Column(db.String, nullable=False, default='preschool')
    status = db.Column(db.String, default='pending')
    notes = db.Column(db.Text, nullable=True)
    next_action = db.Column(db.String, nullable=True)
    next_action_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Closed-won tracking and finder/map data (migration 20261029_accounts_portfolio.sql).
    closed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    closed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    place_id = db.Column(db.String, nullable=True, index=True)
    lat = db.Column(db.Float, nullable=True)
    lng = db.Column(db.Float, nullable=True)
    website = db.Column(db.String, nullable=True)

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('sales_schools', lazy=True))
    closed_by = db.relationship('User', foreign_keys=[closed_by_id])

    def get_all_emails(self):
        """Get all emails for this school (primary + additional)"""
        emails = [self.email]
        if self.additional_emails:
            try:
                additional = json.loads(self.additional_emails)
                if isinstance(additional, list):
                    emails.extend([item.strip() for item in additional
                                   if isinstance(item, str) and item.strip()])
            except (json.JSONDecodeError, TypeError):
                pass
        return emails
    
    def set_additional_emails(self, email_list):
        """Set additional emails from a list"""
        if email_list and isinstance(email_list, list):
            seen = {self.email.strip().casefold()}
            filtered_emails = []
            for item in email_list:
                candidate = item.strip()
                if candidate and candidate.casefold() not in seen:
                    filtered_emails.append(candidate)
                    seen.add(candidate.casefold())
            self.additional_emails = json.dumps(filtered_emails) if filtered_emails else None
        else:
            self.additional_emails = None

class SentEmail(db.Model):
    __tablename__ = 'sent_emails'
    id = db.Column(db.Integer, primary_key=True)
    school_name = db.Column(db.String, nullable=False)
    school_email = db.Column(db.String, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded = db.Column(db.Boolean, default=False)
    followup_sent = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sales_school_id = db.Column(db.Integer, db.ForeignKey('sales_schools.id', ondelete='SET NULL'), nullable=True)
    
    # Keep old fields for backward compatibility
    reply_content = db.Column(db.Text, nullable=True)
    reply_subject = db.Column(db.String, nullable=True) 
    reply_date = db.Column(db.DateTime, nullable=True)
    reply_sender = db.Column(db.String, nullable=True)
    
    # New fields for multiple replies
    reply_count = db.Column(db.Integer, default=0)
    last_reply_date = db.Column(db.DateTime, nullable=True)
    
# New model for storing email replies
class EmailReply(db.Model):
    __tablename__ = 'email_replies'
    id = db.Column(db.Integer, primary_key=True)
    sent_email_id = db.Column(db.Integer, db.ForeignKey('sent_emails.id'), nullable=False)
    reply_content = db.Column(db.Text, nullable=False)
    reply_subject = db.Column(db.String, nullable=True)
    reply_date = db.Column(db.DateTime, nullable=False)
    reply_sender = db.Column(db.String, nullable=True)
    reply_message_id = db.Column(db.String, nullable=True)  # To avoid duplicates
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # KEEP ONLY THIS RELATIONSHIP DEFINITION
    sent_email = db.relationship('SentEmail', backref=db.backref('replies', lazy=True, cascade='all, delete-orphan'))


class SentMessage(db.Model):
    """A message identifier for each successful outbound send in a conversation."""
    __tablename__ = 'sent_messages'
    id = db.Column(db.Integer, primary_key=True)
    sent_email_id = db.Column(db.Integer, db.ForeignKey('sent_emails.id'), nullable=False)
    message_id = db.Column(db.String, unique=True, nullable=False)
    subject = db.Column(db.String, nullable=False)
    kind = db.Column(db.String, nullable=False)
    sent_at = db.Column(db.DateTime, nullable=False, default=lambda: utc_now())
    sent_email = db.relationship('SentEmail', backref=db.backref('outbound_messages', lazy=True, cascade='all, delete-orphan'))


class MailSyncState(db.Model):
    __tablename__ = 'mail_sync_states'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    uidvalidity = db.Column(db.String, nullable=True)
    last_uid = db.Column(db.BigInteger, nullable=False, default=0)
    pending_count = db.Column(db.Integer, nullable=False, default=0)
    last_checked_at = db.Column(db.DateTime, nullable=True)
    last_success_at = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.String, nullable=True)


class GeocodedAddress(db.Model):
    __tablename__ = 'geocoded_addresses'
    address_key = db.Column(db.String, primary_key=True)
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    checked_at = db.Column(db.DateTime, nullable=False, default=lambda: utc_now())


class MapSnapshot(db.Model):
    __tablename__ = 'map_snapshots'
    id = db.Column(db.Integer, primary_key=True)
    data_json = db.Column(db.Text, nullable=False, default='{}')
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: utc_now())


class SalesTask(db.Model):
    __tablename__ = 'sales_tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(240), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    school_id = db.Column(db.Integer, db.ForeignKey('sales_schools.id', ondelete='SET NULL'))
    due_at = db.Column(db.DateTime)
    priority = db.Column(db.String(10), nullable=False, default='normal')
    status = db.Column(db.String(12), nullable=False, default='open')
    version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: utc_now())
    completed_at = db.Column(db.DateTime)
    owner = db.relationship('User')
    school = db.relationship('SalesSchool')


class SchoolActivity(db.Model):
    __tablename__ = 'school_activities'
    id = db.Column(db.Integer, primary_key=True)
    sales_school_id = db.Column(db.Integer, db.ForeignKey('sales_schools.id', ondelete='CASCADE'), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    kind = db.Column(db.String, nullable=False)
    detail = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: utc_now())
    school = db.relationship('SalesSchool', backref=db.backref('activities', lazy=True, cascade='all, delete-orphan'))

# ====================================================
# GOOGLE SHEETS DATA MANAGEMENT
# ====================================================

def load_PSA_school_sheet():
    """Load the new Google Sheet for PSA Preschools and Happy Feet."""
    scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
    service_account_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    service_account_info = json.loads(service_account_json)
    service_account_info["private_key"] = service_account_info["private_key"].replace("\\n", "\n")
    creds = ServiceAccountCredentials.from_json_keyfile_dict(service_account_info, scope)
    client = gspread.authorize(creds)
    sheet = client.open('PSA Preschools')
    worksheet = sheet.sheet1
    rows = worksheet.get_all_values()
    return rows

def split_sheet_schools(sheet_rows):
    """
    Splits sheet rows into PSA Preschools, Happy Feet, and Elementary/Catholic schools based on indicator rows.
    """
    psa_preschools = []
    happy_feet = []
    elementary_catholic = []
    mode = None
    
    # ADD THIS DEBUG LINE AT THE START
    print(f"DEBUG: Processing {len(sheet_rows)} rows from sheet")
    
    for row in sheet_rows:
        if len(row) < 15:
            continue
        indicator = str(row[1]).strip().lower()
        
        # ADD MORE DETAILED LOGGING
        if "elementary" in indicator or "psa" in indicator or "happyfeet" in indicator:
            print(f"DEBUG: Found potential header: '{indicator}' (original: '{row[1]}')")
        
        # Check for section headers
        if indicator == "psa preschool" or indicator == "northern virginia (psa)":
            mode = "psa"
            print(f"DEBUG: Switched to PSA mode")
            continue
        elif indicator == "happyfeet preschool" or indicator == "northern virginia (happyfeet)":
            mode = "happyfeet"
            print(f"DEBUG: Switched to HappyFeet mode")
            continue
        elif indicator == "elementary": 
            mode = "elementary"
            print(f"DEBUG: Switched to ELEMENTARY mode with header: '{indicator}'")
            continue
        
        # Extract school data based on mode
        if mode == "psa":
            name = str(row[1]).strip()
            address = str(row[13]).strip()
            if not name or not address or name.lower() in GENERIC_NAMES:
                continue
            psa_preschools.append({"name": name, "address": address})
            
        elif mode == "happyfeet":
            name = str(row[1]).strip()
            address = str(row[14]).strip()
            if not name or not address or name.lower() in GENERIC_NAMES:
                continue
            happy_feet.append({"name": name, "address": address})
            
        elif mode == "elementary":
            name = str(row[1]).strip()
            address = str(row[14]).strip()
            if not name or not address or name.lower() in GENERIC_NAMES:
                continue
            print(f"DEBUG: Added elementary school: {name} at {address}")
            elementary_catholic.append({"name": name, "address": address})
    
    # ADD SUMMARY LOGGING
    print(f"DEBUG: Final counts - PSA: {len(psa_preschools)}, HappyFeet: {len(happy_feet)}, Elementary: {len(elementary_catholic)}")
    
    return psa_preschools, happy_feet, elementary_catholic

GENERIC_NAMES = {"elementary", "preschool", "school name", "elementary school"}
MAP_SCHOOL_CACHE = {}

REC_SITES = [
    {"name": "Hanson Park", "address": "22831 Hanson Park Dr, Aldie, VA 20105"},
    {"name": "Heron Overlook", "address": "20550 Heron overlook Plz, Ashburn, VA 20147"}
]

# ====================================================
# UTILITY FUNCTIONS
# ====================================================

def normalize_name(name):
    """Lowercase, remove non-alphanumeric, and extra spaces for fuzzy matching."""
    if not name:
        return ""
    name = name.lower()
    name = re.sub(r'[^a-z0-9 ]', '', name)
    name = re.sub(r'\s+', ' ', name)
    return name.strip()

def haversine(lat1, lng1, lat2, lng2):
    """Calculate the great-circle distance between two points."""
    R = 6371  # Earth radius in km
    dlat = radians(lat2 - lat1)
    dlng = radians(lng2 - lng1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlng/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

def geocode_cache_valid(entry):
    if not entry:
        return False
    lifetime = timedelta(days=180) if entry.lat is not None else timedelta(hours=1)
    return entry.checked_at >= utc_now() - lifetime


def geocode_address(address):
    """Reuse saved coordinates and bound network requests to the provider."""
    if not address:
        return None, None
    key = normalize_name(address)
    cached = db.session.get(GeocodedAddress, key)
    if geocode_cache_valid(cached):
        return cached.lat, cached.lng
    try:
        response = requests.get('https://geocode.search.hereapi.com/v1/geocode',
            params={'q': address, 'apiKey': os.getenv('HERE_API_KEY'), 'limit': 1}, timeout=12)
        response.raise_for_status()
        items = response.json().get('items') or []
        position = items[0].get('position', {}) if items else {}
        lat, lng = position.get('lat'), position.get('lng')
        if lat is not None and (not isinstance(lat, (int, float)) or not isinstance(lng, (int, float))
                or not isfinite(lat) or not isfinite(lng) or abs(lat) > 90 or abs(lng) > 180):
            lat, lng = None, None
    except (requests.RequestException, ValueError, TypeError, KeyError):
        app.logger.warning('Geocoding provider could not complete a request')
        lat, lng = None, None
    if cached and cached.lat is not None and (lat is None or lng is None):
        cached.checked_at = utc_now() - timedelta(days=180) + timedelta(hours=1)
        db.session.commit()
        return cached.lat, cached.lng
    if cached:
        cached.lat, cached.lng, cached.checked_at = lat, lng, utc_now()
    else:
        db.session.add(GeocodedAddress(address_key=key, lat=lat, lng=lng, checked_at=utc_now()))
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.warning('Could not persist geocode cache entry')
    return lat, lng

def extract_email_from_string(email_string):
    """Extract email address from 'Name <email@domain.com>' format"""
    print(f"DEBUG: Extracting email from: {email_string}")
    
    # Try to find email in angle brackets first
    bracket_match = re.search(r'<([^>]+)>', email_string)
    if bracket_match:
        email = bracket_match.group(1).strip()
        print(f"DEBUG: Found email in brackets: {email}")
        return email
    
    # Try to find standalone email
    email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_string)
    if email_match:
        email = email_match.group(1).strip()
        print(f"DEBUG: Found standalone email: {email}")
        return email
    
    # If nothing found, return the original string cleaned up
    result = email_string.strip()
    print(f"DEBUG: No email pattern found, returning: {result}")
    return result

# ====================================================
# EMAIL REPLY CHECKING SYSTEM
# ====================================================

MAIL_SYNC_BATCH_LIMIT = 60
MAIL_SYNC_LOOKBACK_DAYS = 90
MAIL_SYNC_FRESHNESS = timedelta(minutes=45)


def mail_sync_status(user_id):
    state = db.session.get(MailSyncState, int(user_id))
    ready = bool(
        state and state.last_success_at and not state.last_error
        and state.pending_count == 0
        and state.last_success_at >= utc_now() - MAIL_SYNC_FRESHNESS
    )
    return {
        "ready": ready,
        "last_checked_at": state.last_checked_at.isoformat() if state and state.last_checked_at else None,
        "last_success_at": state.last_success_at.isoformat() if state and state.last_success_at else None,
        "pending_count": state.pending_count if state else 0,
        "error": state.last_error if state else None,
    }


def _mail_uidvalidity(mail):
    _status, values = mail.response('UIDVALIDITY')
    if not values or not values[0]:
        raise RuntimeError('Mailbox did not report UIDVALIDITY')
    value = values[0]
    return value.decode('ascii') if isinstance(value, bytes) else str(value)


def _mail_date(message):
    try:
        value = email.utils.parsedate_to_datetime(message.get('Date'))
        if value:
            return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    except (TypeError, ValueError, OverflowError):
        pass
    return utc_now()


def _plain_reply(message):
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.get_content_type() != 'text/plain' or part.get_content_disposition() == 'attachment':
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            content = (part.get_payload(decode=True) or b'').decode('utf-8', errors='replace')
        if isinstance(content, str):
            return re.sub(r'\n\s*\n\s*\n', '\n\n', content).strip()[:8000]
    return ''


def _is_human_reply(message, mailbox_address):
    sender = email.utils.parseaddr(message.get('From') or '')[1].strip().casefold()
    if not sender or sender == mailbox_address.casefold():
        return False
    if sender.split('@', 1)[0] in ('mailer-daemon', 'postmaster'):
        return False
    if str(message.get('Auto-Submitted') or 'no').casefold() != 'no':
        return False
    if str(message.get('Precedence') or '').casefold() in ('bulk', 'junk', 'list'):
        return False
    return not message.get('List-Id')


def _reply_record(message, outbound_by_id, sent_by_address):
    # Exact threading headers take precedence over the sender-address fallback
    # needed for mail sent before outbound Message-IDs were stored.
    references = (message.get('References') or '') + ' ' + (message.get('In-Reply-To') or '')
    for message_id in reversed(re.findall(r'<[^>]+>', references)):
        if message_id in outbound_by_id:
            return outbound_by_id[message_id]

    sender = email.utils.parseaddr(message.get('From') or '')[1].strip().lower()
    sent_at = _mail_date(message)
    return next(
        (record for record in sent_by_address.get(sender, []) if record.sent_at <= sent_at),
        None,
    )


def sync_user_mailbox(user, max_messages=MAIL_SYNC_BATCH_LIMIT):
    """Advance one employee's durable IMAP UID cursor in a bounded batch."""
    state = MailSyncState.query.filter_by(user_id=user.id).with_for_update().first()
    if state is None:
        state = MailSyncState(user_id=user.id, last_uid=0, pending_count=0)
        db.session.add(state)
        db.session.flush()

    mailbox = None
    try:
        password = user_mail_password(user)
        mailbox = imaplib.IMAP4_SSL('imap.gmail.com', 993, ssl_context=ssl.create_default_context(), timeout=15)
        mailbox.login(user.email, password)
        selected, _data = mailbox.select('INBOX', readonly=True)
        if selected != 'OK':
            raise RuntimeError('Could not select inbox')
        validity = _mail_uidvalidity(mailbox)
        if state.uidvalidity != validity:
            state.uidvalidity = validity
            state.last_uid = 0
            state.last_success_at = None

        lookback = utc_now() - timedelta(days=MAIL_SYNC_LOOKBACK_DAYS)
        since = lookback.strftime('%d-%b-%Y')
        result, data = mailbox.uid('SEARCH', None, 'UID', f'{state.last_uid + 1}:*', 'SINCE', since)
        if result != 'OK':
            raise RuntimeError('Mailbox search failed')
        all_uids = sorted(int(item) for item in (data[0] or b'').split())
        pending = [uid for uid in all_uids if uid > state.last_uid]
        batch = pending[:max_messages]

        records = SentEmail.query.filter(
            SentEmail.user_id == user.id, SentEmail.sent_at >= lookback,
        ).all()
        record_by_id = {record.id: record for record in records}
        outbound_by_id = {
            item.message_id: record_by_id[item.sent_email_id]
            for item in SentMessage.query.join(SentEmail).filter(
                SentEmail.user_id == user.id, SentEmail.sent_at >= lookback,
            ).all()
            if item.sent_email_id in record_by_id
        }
        tracked_ids = {record.id for record in outbound_by_id.values()}
        sent_by_address = {}
        for record in sorted(records, key=lambda item: item.sent_at, reverse=True):
            if record.id not in tracked_ids:
                sent_by_address.setdefault(record.school_email.strip().lower(), []).append(record)
        seen_ids = {
            message_id for (message_id,) in db.session.query(EmailReply.reply_message_id)
            .join(SentEmail).filter(SentEmail.user_id == user.id, SentEmail.sent_at >= lookback).all() if message_id
        }

        found = 0
        checked = 0
        deadline = time.monotonic() + 25
        for uid in batch:
            if time.monotonic() >= deadline:
                break
            result, pieces = mailbox.uid('FETCH', str(uid), '(BODY.PEEK[])')
            payload = next(
                (part[1] for part in (pieces or []) if isinstance(part, tuple)
                 and len(part) > 1 and isinstance(part[1], bytes)), None,
            )
            if result != 'OK' or payload is None:
                raise RuntimeError('Mailbox message fetch failed')
            message = BytesParser(policy=policy.default).parsebytes(payload)
            message_id = (message.get('Message-ID') or '').strip() or f'imap:{user.id}:{validity}:{uid}'
            if message_id not in seen_ids and _is_human_reply(message, user.email):
                record = _reply_record(message, outbound_by_id, sent_by_address)
                if record:
                    received_at = _mail_date(message)
                    db.session.add(EmailReply(
                        sent_email_id=record.id,
                        reply_content=_plain_reply(message),
                        reply_subject=str(message.get('Subject') or ''),
                        reply_date=received_at,
                        reply_sender=str(message.get('From') or ''),
                        reply_message_id=message_id,
                    ))
                    record.responded = True
                    record.reply_count = (record.reply_count or 0) + 1
                    record.last_reply_date = received_at
                    if record.reply_count == 1:
                        record.reply_content = _plain_reply(message)
                        record.reply_subject = str(message.get('Subject') or '')
                        record.reply_date = received_at
                        record.reply_sender = str(message.get('From') or '')
                    if record.sales_school_id:
                        school = db.session.get(SalesSchool, record.sales_school_id)
                        if school and school.status in ('pending', 'contacted'):
                            school.status = 'replied'
                    seen_ids.add(message_id)
                    found += 1
            state.last_uid = uid
            checked += 1

        remaining = len(pending) - checked
        state.pending_count = remaining
        state.last_checked_at = utc_now()
        state.last_error = None
        if remaining == 0:
            state.last_success_at = state.last_checked_at
        else:
            state.last_success_at = None
        db.session.commit()
        return {"replies_found": found, "messages_checked": checked,
                "pending_count": remaining, **mail_sync_status(user.id)}
    except Exception as exc:
        db.session.rollback()
        state = db.session.get(MailSyncState, user.id)
        if state is None:
            state = MailSyncState(user_id=user.id, last_uid=0, pending_count=0)
            db.session.add(state)
        state.last_checked_at = utc_now()
        credential_error = isinstance(exc, MailCredentialUnavailable)
        state.last_error = ('Stored mail credential is unavailable. Save a new Gmail app password.'
                            if credential_error else
                            'Mailbox check failed. Check the Gmail app password and try again.')
        state.last_success_at = None
        db.session.commit()
        logging.exception('Mailbox sync failed for user %s', user.id)
        if credential_error:
            raise
        raise RuntimeError('Mailbox check failed. Check the Gmail app password and try again.') from exc
    finally:
        if mailbox:
            try:
                mailbox.logout()
            except Exception:
                pass


def check_user_email_replies(user):
    return sync_user_mailbox(user)["replies_found"]


def check_user_email_replies_limited(user, max_emails_to_check=MAIL_SYNC_BATCH_LIMIT,
                                     max_replies_to_process=None):
    return sync_user_mailbox(user, max_messages=max_emails_to_check)["replies_found"]


def check_email_replies():
    """Best-effort background sweep. Manual checks also run when employees open Email Center."""
    with app.app_context():
        users = User.query.filter(
            User.email_password.isnot(None),
            User.id.in_(db.session.query(SentEmail.user_id).distinct()),
        ).order_by(User.id).all()
        for user in users:
            try:
                sync_user_mailbox(user)
            except Exception:
                logging.exception('Background mailbox sync failed for user %s', user.id)


# ====================================================
# SCHEDULER CONFIGURATION
# ====================================================

# Configure logging for scheduler
logging.basicConfig(level=logging.INFO)
scheduler_logger = logging.getLogger('apscheduler')

# Initialize scheduler with better configuration
executors = {
    'default': ThreadPoolExecutor(20)
}
job_defaults = {
    'coalesce': False,
    'max_instances': 1,
    'misfire_grace_time': 300  # 5 minutes grace period
}

scheduler = BackgroundScheduler(
    executors=executors,
    job_defaults=job_defaults,
    timezone='UTC'
)

def start_scheduler():
    """Start the background scheduler for checking email replies"""
    try:
        if not scheduler.running:
            # Check for email replies every 30 minutes
            scheduler.add_job(
                func=check_email_replies,
                trigger="interval",
                minutes=30,
                id='email_reply_checker',
                replace_existing=True,
                misfire_grace_time=600  # 10 minutes grace period
            )
            
            # Add a heartbeat job to verify scheduler is working
            scheduler.add_job(
                func=lambda: print(f"Scheduler heartbeat: {datetime.utcnow()}"),
                trigger="interval",
                minutes=10,
                id='scheduler_heartbeat',
                replace_existing=True
            )
            
            scheduler.start()
            print(f"✅ Email reply checker scheduled to run every 30 minutes")
            print(f"✅ Scheduler heartbeat every 10 minutes")
            
            # Shut down the scheduler when exiting the app
            atexit.register(lambda: scheduler.shutdown(wait=False))
            
        return True
    except Exception as e:
        print(f"❌ Failed to start scheduler: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

# Start the scheduler when the app starts
scheduler_disabled = os.getenv('PSA_DISABLE_SCHEDULER', '').lower() == 'true'
scheduler_started = False if scheduler_disabled else start_scheduler()
if scheduler_disabled:
    app.logger.info('In-process reply scheduler disabled for this process')
else:
    print(f"Scheduler initialization: {'✅ Success' if scheduler_started else '❌ Failed'}")

# ====================================================
# EMAIL TEMPLATES
# ====================================================

# Template for Preschools
PRESCHOOL_EMAIL_TEMPLATE = """
Hello {{ contact_name }},

My name is {{ user_name }}, and I'm with The Players Sports Academy (PSA) - a nonprofit organization offering fun, convenient sports activities for preschool students ages 2-5 right on campus during the school day. 

It was a pleasure visiting {{ school_name }} recently! I'd love to share more information about our on-site sports programs specifically designed for your preschoolers.

PSA TOTS currently works with over 60 preschools in the Northern Virginia area, providing quality sports programs designed specifically for young learners ages 2-5.

Here's why preschools and families love working with PSA:
- On-site convenience - Programs run during school hours with no extra work for your team
- Age-appropriate activities - All programs designed specifically for 2-5 year olds
- All equipment provided - I bring everything needed for each session
- Flexible scheduling - Programs available seasonally or year-round
- Variety of activities - Soccer, Basketball, T-Ball, and Yoga designed for preschoolers
- Fundraising opportunity - Schools can raise funds through the programs
- Professional coaching - All coaches are trained in early childhood development

We would love to set up a free demo session so your students can experience the fun firsthand!

Would you be open to a quick call or meeting to discuss the details? Please let me know a date and time that works best for you.

I've attached our preschool program overview for your review.

Thank you for your time, and I look forward to the opportunity to work together!

Best regards,
{{ user_name }}
Sales Associate and Coach
{{ user_email }}
https://thepsasports.com
"""

# Template for Elementary Schools
ELEMENTARY_EMAIL_TEMPLATE = """
Hello {{ contact_name }},

My name is {{ user_name }}, and I'm with The Players Sports Academy (PSA) - a nationally recognized nonprofit specializing in after-school athletic enrichment for elementary students.

It was a pleasure visiting {{ school_name }} recently! I'd love to share more information about our comprehensive sports programs designed for elementary-aged children.

PSA currently partners with numerous elementary schools in the area, providing quality sports programs that complement your educational mission.

Here's why elementary schools and families choose PSA:
- No cost to the school - Parents enroll directly, and we offer a revenue-share model to support your PTA or school initiatives.
- Hassle-free - We handle everything: professional coaches, equipment, registration, and student pick-up after each session.
- Flexible offerings - Programs run seasonally (6-8 weeks) with options like soccer, basketball, flag football, and more.
- Community-focused - We provide scholarships and fundraising support to help all students participate.

We offer both recreational and competitive program options to meet the diverse needs of your student body.

Would you be interested in scheduling a brief meeting to discuss how PSA can enhance your school's athletic offerings? I'm happy to work around your schedule.

I've attached detailed information about our elementary programs and partnership options.

Thank you for your time and consideration!

Best regards,
{{ user_name }}
Sales Associate and Coach
{{ user_email }}
https://thepsasports.com
"""

# Add this new template with the other email templates
PRIVATE_SCHOOL_EMAIL_TEMPLATE = """
Hi {{ contact_name }},

My name is Coach {{ user_name }}, and I'm with The Players Sports Academy (PSA) — a nationally recognized nonprofit specializing in after-school athletic enrichment for elementary students. I have attached our flyer as well as some recommendation letters to this email to review at your convenience.

We partner with dozens of diocese schools across Northern Virginia to provide fun, convenient, and high-quality sports programs right on school grounds.

Here's why schools and families love working with PSA:

No cost to the school – Parents enroll directly, and we offer a revenue-share model to support your PTA or school initiatives.

Hassle-free – We handle everything: professional coaches, equipment, registration, and student pick-up after each session.

Flexible offerings – Programs run seasonally (6–8 weeks) with options like soccer, basketball, flag football, and more.

Community-focused – We provide scholarships and fundraising support to help all students participate.

We currently run successful programs at St. Theresa, St. Veronica, St. Agnes, and over a dozen more diocese schools. Would love to bring the same energy and opportunity to your school!

Would you be open to a quick call to discuss? Feel free to let me know a time that works for you. Be sure to check out those recommendation letters from within the diocese I attached for you.

Thank you for your time, and I look forward to the opportunity to work together!

Best regards,
{{ user_name }}
Sales Associate and Coach
{{ user_email }}
www.thepsasports.com
"""

# Follow up
PRESCHOOL_FOLLOWUP_TEMPLATE = """
Hello there,

I wanted to follow up on my previous email regarding PSA's on-site preschool sports programs for {{ school_name }}. 

Our PSA TOTS program has been incredibly successful at preschools throughout Northern Virginia, helping children ages 2-5 develop fundamental motor skills while having fun.

We would love to set up a free demo session for your preschoolers to experience our age-appropriate activities firsthand.

Please let me know if you have any questions or would like to schedule a quick call to discuss further.

Best regards,  
{{ user_name }}  
Sales Associate and Coach  
{{ user_email }}
https://thepsports.com
"""

ELEMENTARY_FOLLOWUP_TEMPLATE = """
Hello there,

I wanted to follow up on my previous email regarding PSA's sports programs for {{ school_name }}.

Our elementary programs have been a great success at schools throughout the region, providing students with quality athletic instruction and character development opportunities.

I'd be happy to discuss how we can customize a program to fit your school's specific needs and schedule.

Please let me know if you have any questions or would like to schedule a brief conversation.

Best regards,  
{{ user_name }}  
Sales Associate and Coach  
{{ user_email }}
https://thepsports.com
"""

# Add private school follow-up template
PRIVATE_SCHOOL_FOLLOWUP_TEMPLATE = """
Hello there,

I wanted to follow up on my previous email regarding PSA's after-school sports programs for {{ school_name }}.

Our programs have been incredibly successful at diocese schools throughout Northern Virginia, providing students with quality athletic instruction while supporting school fundraising initiatives.

I'd be happy to discuss how we can customize a program to fit your school's specific needs and schedule.

Please let me know if you have any questions or would like to schedule a brief conversation.

Best regards,  
{{ user_name }}  
Sales Associate and Coach  
{{ user_email }}
www.thepsasports.com
"""

# ====================================================
# API ENDPOINTS - USER AUTHENTICATION
# ====================================================

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request"}), 400
    if not isinstance(data.get("name"), str) or not isinstance(data.get("email"), str):
        return jsonify({"error": "Missing required fields"}), 400
    name = data["name"].strip()
    email = data["email"].strip().lower()
    phone = data.get("phone")
    password = data.get("password")
    invite_token = data.get("invite_token")
    
    if (not all([name, email, password, invite_token]) or
            not isinstance(password, str) or not isinstance(invite_token, str) or
            len(invite_token) > 256):
        return jsonify({"error": "Missing required fields"}), 400

    token_hash = hashlib.sha256(invite_token.encode("utf-8")).hexdigest()
    invitation = EmployeeInvitation.query.filter_by(token_hash=token_hash).with_for_update().first()
    now = utc_now()
    if (not invitation or invitation.email != email or invitation.used_at or
            invitation.revoked_at or invitation.expires_at <= now):
        return jsonify({"error": "Invalid or expired invitation"}), 403

    if User.query.filter(func.lower(User.email) == email).first():
        return jsonify({"error": "Email already registered"}), 400

    user = User(name=name, email=email, phone=phone)
    user.set_password(password)
    db.session.add(user)
    invitation.used_at = now
    for other in EmployeeInvitation.query.filter(
        EmployeeInvitation.email == email,
        EmployeeInvitation.id != invitation.id,
        EmployeeInvitation.used_at.is_(None),
        EmployeeInvitation.revoked_at.is_(None),
    ).all():
        other.revoked_at = now
    db.session.commit()
    
    return jsonify({"message": "User registered successfully"})

@app.route("/api/invitations", methods=["GET"])
@jwt_required()
def list_invitations():
    error = admin_access_error()
    if error:
        return error
    invitations = EmployeeInvitation.query.filter(
        EmployeeInvitation.used_at.is_(None),
        EmployeeInvitation.revoked_at.is_(None),
        EmployeeInvitation.expires_at > utc_now(),
    ).order_by(EmployeeInvitation.expires_at.desc()).all()
    return jsonify([{
        "id": invite.id,
        "email": invite.email,
        "expires_at": invite.expires_at.isoformat() + "Z",
    } for invite in invitations])

@app.route("/api/invitations", methods=["POST"])
@jwt_required()
def create_invitation():
    error = admin_access_error()
    if error:
        return error
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("email"), str):
        return jsonify({"error": "Enter a valid employee email"}), 400
    email = data["email"].strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "Enter a valid employee email"}), 400
    if User.query.filter(func.lower(User.email) == email).first():
        return jsonify({"error": "An account already uses this email"}), 409

    token = secrets.token_urlsafe(32)
    invite = EmployeeInvitation(
        email=email,
        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        created_by=int(get_jwt_identity()),
        expires_at=utc_now() + timedelta(days=7),
    )
    db.session.add(invite)
    db.session.commit()
    return jsonify({
        "id": invite.id,
        "email": invite.email,
        "token": token,
        "expires_at": invite.expires_at.isoformat() + "Z",
    }), 201

@app.route("/api/invitations/<int:invitation_id>", methods=["DELETE"])
@jwt_required()
def revoke_invitation(invitation_id):
    error = admin_access_error()
    if error:
        return error
    invite = EmployeeInvitation.query.filter_by(id=invitation_id).with_for_update().first()
    if not invite or invite.used_at or invite.revoked_at:
        return jsonify({"error": "Invitation not found"}), 404
    invite.revoked_at = utc_now()
    db.session.commit()
    return jsonify({"message": "Invitation revoked"})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=str(user.id))
        return jsonify({
            "access_token": access_token,
            "user": {
                "id": user.id, 
                "name": user.name, 
                "email": user.email, 
                "phone": user.phone,
                "admin": user.admin,
                "mail_connected": bool(user.email_password)
            }
        })
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": user.id, 
        "name": user.name, 
        "email": user.email, 
        "phone": user.phone,
        "admin": user.admin,
        "mail_connected": bool(user.email_password)
    })

# ====================================================
# API ENDPOINTS - EMAIL SETTINGS
# ====================================================

@app.route("/api/email-settings", methods=["POST"])
@jwt_required()
def save_email_settings():
    data = request.get_json(silent=True) or {}
    email_password = data.get("email_password")
    
    if not isinstance(email_password, str) or not email_password.strip():
        return jsonify({"error": "Email password required"}), 400
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    user.email_password = encrypt_password(email_password)
    state = db.session.get(MailSyncState, user.id)
    if state is None:
        db.session.add(MailSyncState(user_id=user.id, last_uid=0, pending_count=0))
    else:
        state.last_success_at = None
        state.last_error = None
    db.session.commit()
    
    return jsonify({"message": "Email settings saved"})


def mail_credential_migration_counts():
    values = db.session.query(User.email_password).filter(User.email_password.isnot(None)).all()
    configured = [row[0] for row in values if row[0]]
    encrypted = 0
    invalid = 0
    for value in configured:
        if is_encrypted(value):
            try:
                decrypt_password(value)
                encrypted += 1
            except MailCredentialUnavailable:
                invalid += 1
    return {
        "configured": len(configured),
        "encrypted": encrypted,
        "invalid": invalid,
        "legacy": len(configured) - encrypted - invalid,
        "legacy_reads_enabled": legacy_reads_enabled(),
    }


@app.route("/api/mail-credential-migration", methods=["GET", "POST"])
@jwt_required()
def mail_credential_migration():
    error = admin_access_error()
    if error:
        return error
    if request.method == "GET":
        return jsonify(mail_credential_migration_counts())

    data = request.get_json(silent=True) or {}
    if data.get("confirm") != "ENCRYPT_EXISTING_MAIL_PASSWORDS":
        return jsonify({"error": "Migration confirmation required"}), 400

    migrated = 0
    try:
        users = User.query.filter(User.email_password.isnot(None)).with_for_update().all()
        for user in users:
            value = user.email_password
            if not value:
                continue
            if is_encrypted(value):
                # Refuse to declare success if an existing token cannot be read.
                decrypt_password(value)
            else:
                user.email_password = encrypt_password(value)
                migrated += 1
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    return jsonify({"migrated": migrated, **mail_credential_migration_counts()})

@app.route("/api/mail-sync-status", methods=["GET"])
@jwt_required()
def current_mail_sync_status():
    user = db.session.get(User, int(get_jwt_identity()))
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"mail_connected": bool(user.email_password), **mail_sync_status(user.id)})


@app.route("/api/check-email-replies", methods=["POST"])
@jwt_required()
def manual_check_email_replies():
    """Advance only the signed-in employee's mailbox; admins have their own inbox."""
    user = db.session.get(User, int(get_jwt_identity()))
    if not user:
        return jsonify({"error": "User not found"}), 404
    if not user.email_password:
        return jsonify({"error": "Email settings not configured"}), 400
    try:
        return jsonify(sync_user_mailbox(user))
    except MailCredentialUnavailable:
        raise
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 502

# ====================================================
# API ENDPOINTS - SCHOOL MANAGEMENT
# ====================================================

from .portfolio import iso_utc, set_school_status, FINISHED_STAGES  # noqa: E402
from .finder import load_saved_index  # noqa: E402

# 'partner' is an active client; 'former' was a client and no longer is.
SCHOOL_STAGES = ('pending', 'contacted', 'replied', 'meeting', 'partner', 'former', 'not_interested')


def school_dict(school):
    additional = school.get_all_emails()[1:]
    return {
        "id": school.id,
        "school_name": school.school_name,
        "contact_name": school.contact_name,
        "email": school.email,
        "additional_emails": additional,
        "all_emails": school.get_all_emails(),
        "phone": school.phone,
        "address": school.address,
        "school_type": school.school_type,
        "status": school.status,
        "notes": school.notes,
        "next_action": school.next_action,
        "next_action_at": school.next_action_at.isoformat() if school.next_action_at else None,
        "created_at": school.created_at.isoformat() if school.created_at else None,
        "user_id": school.user_id,
        "user_name": school.user.name if school.user else None,
        "owner_name": school.user.name if school.user else None,
        "closed_at": iso_utc(school.closed_at),
        "closed_by_id": school.closed_by_id,
        "closed_by_name": school.closed_by.name if school.closed_by else None,
        "lat": school.lat,
        "lng": school.lng,
        "place_id": school.place_id,
        "website": school.website,
    }


def normalized(value):
    return (value or '').strip().casefold()


def valid_email(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', value.strip()))


def school_conflict(name, address, emails, candidates=None):
    """Find an existing team assignment before another employee contacts it."""
    candidates = candidates if candidates is not None else SalesSchool.query.all()
    wanted_emails = {normalized(item) for item in emails if normalized(item)}
    for school in candidates:
        if wanted_emails.intersection(normalized(item) for item in school.get_all_emails()):
            return school
        if normalized(school.school_name) == normalized(name) and address and school.address:
            if normalized(school.address) == normalized(address):
                return school
    return None


def accessible_school(school_id):
    user = db.session.get(User, int(get_jwt_identity()))
    school = db.session.get(SalesSchool, school_id)
    if not user or not school or (not user.admin and school.user_id != user.id):
        return None, user
    return school, user


def school_timeline(school):
    records = SentEmail.query.filter(or_(
        SentEmail.sales_school_id == school.id,
        and_(SentEmail.sales_school_id.is_(None), SentEmail.user_id == school.user_id,
             func.lower(SentEmail.school_name) == school.school_name.lower()),
    )).all()
    items = []
    school_emails = {normalized(item) for item in school.get_all_emails()}
    for record in records:
        if record.sales_school_id is None and normalized(record.school_email) not in school_emails:
            continue
        messages = SentMessage.query.filter_by(sent_email_id=record.id).all()
        if messages:
            items.extend({
                "kind": message.kind, "at": message.sent_at.isoformat(),
                "detail": f"{message.subject} to {record.school_email}",
            } for message in messages)
        else:
            items.append({"kind": "outreach", "at": record.sent_at.isoformat(),
                          "detail": f"Email sent to {record.school_email}"})
        items.extend({
            "kind": "received", "at": reply.reply_date.isoformat(),
            "detail": reply.reply_content,
            "subject": reply.reply_subject,
            "sender": reply.reply_sender,
        } for reply in EmailReply.query.filter_by(sent_email_id=record.id).all())
    items.extend({
        "kind": activity.kind, "at": activity.created_at.isoformat(),
        "detail": activity.detail,
        "actor": db.session.get(User, activity.actor_id).name if db.session.get(User, activity.actor_id) else None,
    } for activity in SchoolActivity.query.filter_by(sales_school_id=school.id).all())
    return sorted(items, key=lambda item: item["at"], reverse=True)[:100]

@app.route("/api/add-school", methods=["POST"])
@jwt_required()
def add_school():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A school record is required"}), 400
    # Leads from the finder come without an email; they can be saved and worked by phone/visit.
    from_finder = bool(data.get('place_id')) or data.get('source') == 'finder'
    raw_email = data.get('email')
    if from_finder and raw_email is None:
        raw_email = ''
    if not isinstance(data.get('school_name'), str) or not isinstance(raw_email, str):
        return jsonify({"error": "School name and email are required"}), 400
    school_name = (data.get("school_name") or '').strip()
    email = raw_email.strip()
    additional_emails = data.get("additional_emails", [])  # New field
    contact_name = data.get("contact_name")
    phone = data.get("phone")
    address = data.get("address")
    school_type = data.get("school_type", "preschool")
    place_id = data.get("place_id")
    lat, lng, website = data.get("lat"), data.get("lng"), data.get("website")

    if not school_name or (not email and not from_finder):
        return jsonify({"error": "School name and email are required"}), 400
    if not isinstance(additional_emails, list) or any(
        not valid_email(item) for item in additional_emails
    ) or (email and not valid_email(email)):
        return jsonify({"error": "Enter valid school email addresses"}), 400
    if school_type not in ['preschool', 'elementary', 'private']:
        return jsonify({"error": "Invalid school type"}), 400
    if place_id is not None and (not isinstance(place_id, str) or len(place_id) > 300):
        return jsonify({"error": "Invalid place identifier"}), 400
    place_id = (place_id or '').strip() or None
    if lat is not None or lng is not None:
        if not (isinstance(lat, (int, float)) and isinstance(lng, (int, float))
                and not isinstance(lat, bool) and not isinstance(lng, bool)
                and isfinite(lat) and isfinite(lng) and abs(lat) <= 90 and abs(lng) <= 180):
            return jsonify({"error": "Enter valid coordinates"}), 400
    if website is not None and (not isinstance(website, str) or len(website) > 500):
        return jsonify({"error": "Invalid website"}), 400
    website = (website or '').strip() or None
    if phone is not None and not isinstance(phone, str):
        return jsonify({"error": "Invalid phone number"}), 400
    
    user_id = get_jwt_identity()

    saved = load_saved_index(db, SalesSchool, User, normalize_name, haversine).match(
        place_id, school_name, address, lat, lng)
    if saved:
        owner_name = saved['owner_name']
        same_owner = saved['owner_id'] == int(user_id)
        return jsonify({
            "error": f"School is already assigned to {owner_name}",
            "existing_id": saved['id'], "owner_name": owner_name,
            "school_id": saved['id'] if same_owner else None,
        }), 409
    existing = school_conflict(school_name, address, [email, *additional_emails])
    
    if existing:
        return jsonify({
            "error": f"School is already assigned to {existing.user.name}",
            "existing_id": existing.id, "owner_name": existing.user.name,
            "school_id": existing.id if existing.user_id == int(user_id) else None,
        }), 409
    
    school = SalesSchool(
        school_name=school_name,
        contact_name=contact_name,
        email=email,
        phone=phone,
        address=address,
        school_type=school_type,
        user_id=user_id,
        place_id=place_id,
        lat=lat,
        lng=lng,
        website=website,
    )
    
    # Set additional emails
    school.set_additional_emails(additional_emails)
    
    db.session.add(school)
    db.session.commit()
    
    return jsonify({"message": "School added successfully", "id": school.id}), 201

@app.route("/api/my-schools", methods=["GET"])
@jwt_required()
def get_my_schools():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # If admin, return all schools; otherwise, return only user's schools
    if user.admin and request.args.get('scope') != 'mine':
        schools = SalesSchool.query.all()
    else:
        schools = SalesSchool.query.filter_by(user_id=user_id).all()
    
    return jsonify([school_dict(school) for school in schools])


@app.route('/api/team-users', methods=['GET'])
@jwt_required()
def team_users():
    error = admin_access_error()
    if error:
        return error
    return jsonify([
        {"id": user.id, "name": user.name, "email": user.email}
        for user in User.query.order_by(User.name).all()
    ])


@app.route('/api/sales-schools/<int:school_id>', methods=['GET', 'PATCH'])
@jwt_required()
def sales_school_workspace(school_id):
    school, user = accessible_school(school_id)
    if not school:
        return jsonify({"error": "School not found"}), 404
    if request.method == 'GET':
        return jsonify({"school": school_dict(school), "timeline": school_timeline(school)})

    data = request.get_json(silent=True) or {}
    allowed = {
        'school_name', 'contact_name', 'email', 'additional_emails', 'phone',
        'address', 'school_type', 'status', 'notes', 'next_action', 'next_action_at', 'user_id',
        'website',
    }
    if not isinstance(data, dict) or not data or any(key not in allowed for key in data):
        return jsonify({"error": "No valid school changes supplied"}), 400
    if 'user_id' in data and not user.admin:
        return jsonify({"error": "Only an administrator can reassign schools"}), 403
    if 'status' in data and data['status'] not in SCHOOL_STAGES:
        return jsonify({"error": "Invalid school stage"}), 400
    if 'school_type' in data and data['school_type'] not in ('preschool', 'elementary', 'private'):
        return jsonify({"error": "Invalid school type"}), 400
    if 'additional_emails' in data and (
        not isinstance(data['additional_emails'], list)
        or any(not valid_email(item) for item in data['additional_emails'])
    ):
        return jsonify({"error": "Additional emails must be a list"}), 400
    if 'user_id' in data:
        try:
            new_owner = db.session.get(User, int(data['user_id']))
        except (TypeError, ValueError):
            new_owner = None
        if not new_owner:
            return jsonify({"error": "Employee not found"}), 400
    if 'next_action_at' in data:
        try:
            raw_date = data['next_action_at']
            next_at = datetime.fromisoformat(raw_date.replace('Z', '+00:00')) if raw_date else None
            if next_at and next_at.tzinfo:
                next_at = next_at.astimezone(timezone.utc).replace(tzinfo=None)
        except (AttributeError, TypeError, ValueError):
            return jsonify({"error": "Invalid next action date"}), 400

    for key in ('school_name', 'email'):
        if key in data and (not isinstance(data[key], str) or not data[key].strip()):
            return jsonify({"error": f"{key.replace('_', ' ').title()} is required"}), 400
    if 'email' in data and not valid_email(data['email']):
        return jsonify({"error": "Enter a valid school email address"}), 400
    for key in ('school_name', 'contact_name', 'email', 'phone', 'address', 'notes', 'next_action', 'website'):
        if key in data and data[key] is not None and not isinstance(data[key], str):
            return jsonify({"error": f"Invalid {key}"}), 400
    if 'email' in data or 'school_name' in data or 'address' in data or 'additional_emails' in data:
        candidate_emails = [data.get('email', school.email), *data.get('additional_emails', school.get_all_emails()[1:])]
        other = school_conflict(
            data.get('school_name', school.school_name), data.get('address', school.address),
            candidate_emails, [item for item in SalesSchool.query.all() if item.id != school.id],
        )
        if other:
            return jsonify({"error": f"School is already assigned to {other.user.name}"}), 409

    changes = []
    for key in ('school_name', 'contact_name', 'email', 'phone', 'address', 'school_type',
                'status', 'notes', 'next_action', 'website'):
        if key in data:
            value = data[key].strip() if isinstance(data[key], str) else data[key]
            if key == 'status':
                # Stamps closed_at/closed_by the first time the school becomes a client.
                if set_school_status(school, value, user.id):
                    changes.append('status')
            elif getattr(school, key) != value:
                setattr(school, key, value)
                changes.append(key.replace('_', ' '))
                if key == 'address':
                    school.lat = school.lng = None  # located again from the new address
    if 'additional_emails' in data:
        before = school.additional_emails
        school.set_additional_emails(data['additional_emails'])
        if before != school.additional_emails:
            changes.append('additional emails')
    if 'next_action_at' in data and school.next_action_at != next_at:
        school.next_action_at = next_at
        changes.append('next action date')
    if 'user_id' in data and school.user_id != new_owner.id:
        SalesTask.query.filter_by(school_id=school.id, status='open').update(
            {SalesTask.user_id: new_owner.id, SalesTask.version: SalesTask.version + 1},
            synchronize_session=False,
        )
        school.user_id = new_owner.id
        changes.append(f'owner to {new_owner.name}')
    if changes:
        db.session.add(SchoolActivity(
            sales_school_id=school.id, actor_id=user.id, kind='updated',
            detail='Updated ' + ', '.join(changes),
        ))
        db.session.commit()
    return jsonify(school_dict(school))


@app.route('/api/sales-schools/<int:school_id>/activity', methods=['POST'])
@jwt_required()
def add_school_activity(school_id):
    school, user = accessible_school(school_id)
    if not school:
        return jsonify({"error": "School not found"}), 404
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "An activity record is required"}), 400
    kind = data.get('kind')
    detail = data.get('detail')
    if kind not in ('note', 'call', 'meeting') or not isinstance(detail, str) or not detail.strip() or len(detail) > 2000:
        return jsonify({"error": "Choose a type and enter a note under 2,000 characters"}), 400
    activity = SchoolActivity(
        sales_school_id=school.id, actor_id=user.id, kind=kind, detail=detail.strip(),
    )
    db.session.add(activity)
    db.session.commit()
    return jsonify({"id": activity.id, "message": "Activity added"}), 201

@app.route("/api/delete-school", methods=["DELETE"])
@jwt_required()
def delete_school():
    data = request.get_json()
    school_id = data.get("school_id")

    if not school_id:
        return jsonify({"error": "Missing school_id"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Find the school - admins can delete any, users only their own
    if user.admin:
        school = SalesSchool.query.get(school_id)
    else:
        school = SalesSchool.query.filter_by(id=school_id, user_id=user_id).first()

    if not school:
        return jsonify({"error": "School not found"}), 404

    try:
        db.session.delete(school)
        db.session.commit()
        return jsonify({"status": "School deleted successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route("/api/schools", methods=["GET"])
@jwt_required()
def get_schools():
    """Return the directory with team assignment hints, never private notes."""
    schools = School.query.all()
    assignments = SalesSchool.query.all()
    user_id = int(get_jwt_identity())
    rows = []
    for item in schools:
        assigned = school_conflict(item.name, item.address, [item.email], assignments)
        rows.append({
            "id": item.id, "name": item.name, "address": item.address,
            "phone": item.phone, "contact": item.contact, "email": item.email,
            "sales_school_id": assigned.id if assigned and assigned.user_id == user_id else None,
            "owner_name": assigned.user.name if assigned else None,
            "assigned": bool(assigned),
        })
    return jsonify(rows)

@app.route("/api/upload-schools-csv", methods=["POST"])
@jwt_required()
def upload_schools_csv():
    """Upload schools from CSV file - supports multiple emails per school and private schools"""
    try:
        user_id = get_jwt_identity()
        
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        if not file.filename.lower().endswith('.csv'):
            return jsonify({"error": "File must be a CSV"}), 400
        
        # Read CSV content
        content = file.read().decode('utf-8')
        csv_reader = csv.DictReader(StringIO(content))
        
        schools_added = 0
        schools_skipped = 0
        errors = []
        schools_dict = {}  # To group schools by name and collect emails
        
        # Column mapping for flexible CSV formats
        def find_column(headers, possible_names):
            headers_lower = [h.lower().strip() for h in headers]
            for name in possible_names:
                if name.lower() in headers_lower:
                    return headers[headers_lower.index(name.lower())]
            return None
        
        headers = csv_reader.fieldnames
        if not headers:
            return jsonify({"error": "CSV file appears to be empty or invalid"}), 400
        
        # Map CSV columns to our fields
        school_name_col = find_column(headers, [
            'school_name', 'school name', 'name', 'school', 'schoolname'
        ])
        email_col = find_column(headers, [
            'email', 'email_address', 'school_email', 'contact_email', 'e-mail'
        ])
        contact_name_col = find_column(headers, [
            'contact_name', 'contact name', 'contact', 'director', 'principal', 'contactname'
        ])
        phone_col = find_column(headers, [
            'phone', 'phone_number', 'telephone', 'tel', 'phonenumber'
        ])
        address_col = find_column(headers, [
            'address', 'school_address', 'location', 'addr'
        ])
        school_type_col = find_column(headers, [
            'school_type', 'type', 'school type', 'category', 'schooltype'
        ])
        
        if not school_name_col or not email_col:
            return jsonify({
                "error": "CSV must contain 'school_name' and 'email' columns (or similar variations)"
            }), 400
        
        print(f"DEBUG: CSV columns mapped - name: {school_name_col}, email: {email_col}")
        
        # First pass: Group schools by name and collect all their emails
        row_count = 0
        for row in csv_reader:
            row_count += 1
            
            try:
                school_name = row.get(school_name_col, '').strip()
                email = row.get(email_col, '').strip()
                contact_name = row.get(contact_name_col, '').strip() if contact_name_col else ''
                phone = row.get(phone_col, '').strip() if phone_col else ''
                address = row.get(address_col, '').strip() if address_col else ''
                school_type = row.get(school_type_col, '').strip().lower() if school_type_col else 'preschool'
                
                # Validate required fields
                if not school_name or not email:
                    errors.append(f"Row {row_count}: Missing school name or email")
                    continue
                
                # Validate email format
                if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                    errors.append(f"Row {row_count}: Invalid email format '{email}'")
                    continue
                
                # Normalize school type
                if school_type in ['preschool', 'pre-school', 'daycare', 'day care', 'pre school']:
                    school_type = 'preschool'
                elif school_type in ['elementary', 'elementary school', 'elem', 'public school']:
                    school_type = 'elementary'
                elif school_type in ['private', 'private school', 'catholic', 'diocese', 'christian']:
                    school_type = 'private'
                else:
                    # Default to preschool if not specified or unrecognized
                    school_type = 'preschool'
                
                # Create unique key for school (case-insensitive)
                school_key = f'{normalized(school_name)}|{normalized(address)}'
                
                if school_key not in schools_dict:
                    # First occurrence of this school
                    schools_dict[school_key] = {
                        'school_name': school_name,
                        'contact_name': contact_name,
                        'phone': phone,
                        'address': address,
                        'school_type': school_type,
                        'emails': [email]
                    }
                else:
                    # Additional occurrence - add email if not already present
                    existing_emails = [e.lower() for e in schools_dict[school_key]['emails']]
                    if email.lower() not in existing_emails:
                        schools_dict[school_key]['emails'].append(email)
                        print(f"DEBUG: Added additional email {email} to {school_name}")
                    
                    # Update other fields if they were empty before but have values now
                    if not schools_dict[school_key]['contact_name'] and contact_name:
                        schools_dict[school_key]['contact_name'] = contact_name
                    if not schools_dict[school_key]['phone'] and phone:
                        schools_dict[school_key]['phone'] = phone
                    if not schools_dict[school_key]['address'] and address:
                        schools_dict[school_key]['address'] = address
                
            except Exception as e:
                errors.append(f"Row {row_count}: Error processing row - {str(e)}")
                continue
        
        print(f"DEBUG: Processed {row_count} rows, found {len(schools_dict)} unique schools")

        # Read existing assignments once; check the whole team to prevent two
        # employees contacting the same school from separate CSV imports.
        existing_schools = SalesSchool.query.all()

        # Second pass: Create database entries
        for school_key, school_data in schools_dict.items():
            try:
                school_name = school_data['school_name']
                emails = school_data['emails']

                if school_conflict(school_name, school_data['address'], emails, existing_schools):
                    schools_skipped += 1
                    continue
                
                # Separate primary email and additional emails
                primary_email = emails[0]
                additional_emails = emails[1:] if len(emails) > 1 else []
                
                # Create new school record
                new_school = SalesSchool(
                    school_name=school_name,
                    contact_name=school_data['contact_name'],
                    email=primary_email,
                    phone=school_data['phone'],
                    address=school_data['address'],
                    school_type=school_data['school_type'],
                    user_id=user_id
                )
                
                # Set additional emails using the helper method
                new_school.set_additional_emails(additional_emails)
                
                db.session.add(new_school)
                existing_schools.append(new_school)
                schools_added += 1
                
                print(f"DEBUG: Added school '{school_name}' with {len(emails)} email(s), type: {school_data['school_type']}")
                
            except Exception as e:
                errors.append(f"Error adding school '{school_data.get('school_name', 'Unknown')}': {str(e)}")
                continue
        
        # Commit all changes
        try:
            db.session.commit()
            print(f"DEBUG: Successfully committed {schools_added} schools to database")
        except Exception as e:
            db.session.rollback()
            print(f"DEBUG: Database commit failed: {str(e)}")
            return jsonify({"error": f"Database error: {str(e)}"}), 500
        
        return jsonify({
            "message": f"CSV processed successfully",
            "schools_added": schools_added,
            "schools_skipped": schools_skipped,
            "total_rows_processed": row_count,
            "unique_schools_found": len(schools_dict),
            "errors": errors[:10]  # Limit errors to first 10
        })
        
    except Exception as e:
        print(f"DEBUG: CSV upload error: {str(e)}")
        return jsonify({"error": f"Failed to process CSV: {str(e)}"}), 500

# ====================================================
# API ENDPOINTS - EMAIL OPERATIONS
# ====================================================

def render_email_text(template, **values):
    # These are trusted application templates producing plain text. The MIME
    # builder escapes the HTML alternative separately, exactly once.
    return app.jinja_env.overlay(autoescape=False).from_string(template).render(**values)


def outreach_fingerprint(job):
    value = {'to': job['to_email'], 'subject': job['subject'], 'body': job['body'], 'attachments': job['pdf_files']}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode('utf-8')).hexdigest()


def outreach_review_signer():
    return URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'], salt='psa-outreach-review-v1')


def build_outreach_jobs(user, schools, subject, send_to_all_emails):
    # Build one send job per (school, email address) pair. Templates/PDFs/body are all
    # precomputed here so the SMTP loop below only has to log in once and send.
    jobs = []
    for school in schools:
        if school.school_type == 'preschool':
            email_template = PRESCHOOL_EMAIL_TEMPLATE
            pdf_files = ["PSA TOTS seasonal flyer.pdf", "PSA TOTS year round flyer.pdf", "PSA TOTS Recommendation (Primrose School).pdf"]
        elif school.school_type == 'private':
            email_template = PRIVATE_SCHOOL_EMAIL_TEMPLATE
            pdf_files = ["PSA After School.pdf", "PSA Recommendation (St. Theresa).pdf"]
        else:  # elementary
            email_template = ELEMENTARY_EMAIL_TEMPLATE
            pdf_files = ["PSA After School.pdf", "PSA Recommendation Letter (Madison Trust ES).pdf"]

        body = render_email_text(
            email_template,
            user_name=user.name,
            user_email=user.email,
            school_name=school.school_name,
            contact_name=school.contact_name or "Director/Administrator"
        )

        emails_to_send = school.get_all_emails() if send_to_all_emails else [school.email]
        for email_address in emails_to_send:
            jobs.append({
                "school": school,
                "to_email": email_address,
                "subject": subject,
                "body": body,
                "pdf_files": pdf_files
            })

    return jobs


@app.post('/api/email-preview')
@jwt_required()
def email_preview():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='Select schools to review'), 400
    if 'kind' in data:
        # New outreach flow: per-school previews with warnings (see outreach.py).
        from .outreach import preview_response
        return preview_response(data)
    ids = data.get('school_ids')
    if (not isinstance(ids, list) or not ids or len(ids) > 100
            or any(type(value) is not int for value in ids)):
        return jsonify(error='Select between 1 and 100 schools'), 400
    user = db.session.get(User, int(get_jwt_identity()))
    if not user:
        return jsonify(error='User not found'), 404
    schools = SalesSchool.query.filter(SalesSchool.id.in_(set(ids)), SalesSchool.user_id == user.id).order_by(SalesSchool.id).all()
    if len(schools) != len(set(ids)):
        return jsonify(error='Send only to schools assigned to you'), 403
    subject = data.get('subject', "Let's Connect! PSA Programs")
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 240 or '\n' in subject or '\r' in subject:
        return jsonify(error='Enter a valid subject'), 400
    jobs = build_outreach_jobs(user, schools, subject, data.get('send_to_all_emails') is True)
    if len(jobs) > 100:
        return jsonify(error='Review at most 100 recipients at a time'), 400
    token = outreach_review_signer().dumps({'uid': user.id, 'fingerprints': {
        str(job['school'].id) + ':' + job['to_email']: outreach_fingerprint(job) for job in jobs}})
    return jsonify(preview_token=token, items=[{'school_id': job['school'].id, 'school_name': job['school'].school_name,
        'to_email': job['to_email'], 'subject': job['subject'], 'body': job['body'],
        'attachments': job['pdf_files']} for job in jobs])


@app.route("/api/send-email", methods=["POST"])
@app.route('/api/crm/outreach/send', methods=['POST'])
@jwt_required()
def send_email():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='Supply an outreach request'), 400
    school_ids = data.get("school_ids", [])
    if (not isinstance(school_ids, list) or not 1 <= len(school_ids) <= 100
            or any(type(value) is not int or value < 1 for value in school_ids)):
        return jsonify(error='Select between 1 and 100 schools'), 400
    subject = data.get("subject", "Let's Connect! PSA Programs")
    send_to_all_emails = data.get("send_to_all_emails") is True
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 240 or '\n' in subject or '\r' in subject:
        return jsonify(error='Enter a valid email subject'), 400

    print(f"DEBUG: Received school_ids: {school_ids}")

    if not school_ids:
        return jsonify({"error": "No schools selected"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 400

    if not user.email_password:
        return jsonify({"error": "Email settings not configured"}), 400

    # Get selected schools
    schools = SalesSchool.query.filter(
        SalesSchool.id.in_(school_ids), SalesSchool.user_id == user_id
    ).all()
    if len(schools) != len(set(school_ids)):
        return jsonify({"error": "Send only to schools assigned to you"}), 403

    if not schools:
        return jsonify({"error": "No valid schools found"}), 400

    jobs = build_outreach_jobs(user, schools, subject, send_to_all_emails)

    if request.path == '/api/crm/outreach/send' or data.get('preview_token'):
        if not isinstance(data.get('preview_token'), str):
            return jsonify(error='Review your messages before sending.'), 409
        try:
            review = outreach_review_signer().loads(data.get('preview_token') or '', max_age=900)
        except BadSignature:
            return jsonify(error='Your message review expired. Review the messages again.'), 409
        if review.get('uid') != user.id or any(
            review.get('fingerprints', {}).get(str(job['school'].id) + ':' + job['to_email']) != outreach_fingerprint(job)
            for job in jobs
        ):
            return jsonify(error='A recipient or message changed. Review the messages again before sending.'), 409

    # A blank or malformed address can never be delivered; report it instead of sending.
    skipped_errors = [
        f"Skipped {job['school'].school_name}: missing or invalid email address"
        for job in jobs if not valid_email(job['to_email'])
    ]
    jobs = [job for job in jobs if valid_email(job['to_email'])]

    print(f"DEBUG: Sending {len(jobs)} emails over a single SMTP connection")

    # One login, one connection reused for every email in this request - this is what
    # actually avoids the request timing out on large batches (previously each email
    # opened its own SMTP connection, plus a blocking 3s sleep between sub-batches).
    results = send_emails_over_connection(user.email, user_mail_password(user), user.name, jobs)

    sent_count = 0
    errors = list(skipped_errors)
    schools_contacted = set()

    for job, success, error in results:
        school = job["school"]
        if success:
            record = SentEmail(
                school_name=school.school_name,
                school_email=job["to_email"],
                user_id=user_id,
                sales_school_id=school.id,
                responded=False,
                followup_sent=False
            )
            db.session.add(record)
            record_outbound_message(record, job.get("message_id"), job["subject"], "outreach")
            sent_count += 1
            schools_contacted.add(school.id)
        else:
            errors.append(f"Failed to send to {school.school_name} ({job['to_email']}): {error}")

    for school in schools:
        if school.id in schools_contacted:
            advance_school_stage(school)

    try:
        db.session.commit()
        print(f"DEBUG: Committed {sent_count} sent emails")
    except Exception as e:
        db.session.rollback()
        print(f"DEBUG: Commit error: {str(e)}")

    return jsonify({
        "status": f"{sent_count} emails sent successfully" if sent_count > 0 else "Failed to send emails",
        "sent_count": sent_count,
        "batches_processed": 1,
        "errors": errors
    })

def render_body_parts(body):
    """
    Turn a plain-text body that may contain **bold** and/or ++larger text++ markers into a
    (plain_text, html) pair - plain text has the markers stripped, html has them converted to
    real <b> tags / bigger font-size spans so the formatting survives in the sent email.
    """
    plain_body = re.sub(r'\+\+(.+?)\+\+', r'\1', body)
    plain_body = re.sub(r'\*\*(.+?)\*\*', r'\1', plain_body)

    escaped = html.escape(body)
    sized = re.sub(r'\+\+(.+?)\+\+', r'<span style="font-size: 1.3em;">\1</span>', escaped)
    bolded = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', sized)
    with_line_breaks = bolded.replace('\n', '<br>\n')
    html_body = f'<html><body style="font-family: sans-serif;">{with_line_breaks}</body></html>'

    return plain_body, html_body


_ENCODED_PDFS = {}
_ENCODED_PDFS_LOCK = threading.Lock()


def encoded_pdf_payload(pdf_path):
    """Base64 text for a PDF, encoded once and reused until the file changes on disk."""
    try:
        info = os.stat(pdf_path)
    except OSError:
        return None
    key = (info.st_mtime_ns, info.st_size)
    with _ENCODED_PDFS_LOCK:
        cached = _ENCODED_PDFS.get(pdf_path)
        if cached and cached[0] == key:
            return cached[1]
    with open(pdf_path, "rb") as handle:
        encoded = base64.encodebytes(handle.read()).decode('ascii')
    with _ENCODED_PDFS_LOCK:
        _ENCODED_PDFS[pdf_path] = (key, encoded)
    return encoded


def build_email_message(from_email, from_name, to_email, subject, body, pdf_files,
                        message_id=None, in_reply_to=None):
    """Build a MIME message with PDF attachments (no network I/O)."""
    msg = MIMEMultipart('mixed')  # Specify multipart type
    msg['From'] = f"{from_name} <{from_email}>"
    msg['To'] = to_email
    msg['Subject'] = subject
    msg['Message-ID'] = message_id or email.utils.make_msgid(domain=from_email.rsplit('@', 1)[-1])
    if in_reply_to:
        msg['In-Reply-To'] = in_reply_to
        msg['References'] = in_reply_to

    # Set charset for the entire message
    msg.set_charset('utf-8')

    # Body as plain text + HTML alternative so **bold** markers render as real bold
    plain_body, html_body = render_body_parts(body)
    alt_part = MIMEMultipart('alternative')
    alt_part.attach(MIMEText(plain_body, 'plain', 'utf-8'))
    alt_part.attach(MIMEText(html_body, 'html', 'utf-8'))
    msg.attach(alt_part)

    pdf_directory = os.path.join(os.path.dirname(__file__), 'pdf_attachments')

    for pdf_file in pdf_files:
        pdf_path = os.path.join(pdf_directory, pdf_file)
        encoded = encoded_pdf_payload(pdf_path)
        if encoded is None:
            print(f"WARNING: PDF file not found: {pdf_path}")
            continue
        part = MIMEBase('application', 'pdf')
        part.set_payload(encoded)
        part['Content-Transfer-Encoding'] = 'base64'
        part.add_header('Content-Disposition', f'attachment; filename="{pdf_file}"')
        msg.attach(part)

    return msg


def open_smtp_connection(from_email, from_password):
    """Open and authenticate a single SMTP connection for reuse across many sends."""
    # A timeout is required here - without one, a stalled reply from Gmail blocks the
    # underlying socket read forever, which gunicorn can only stop by killing the whole
    # worker (an uncatchable SystemExit), losing the entire in-progress batch.
    server = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
    server.starttls()
    server.login(from_email, from_password)
    return server


def send_email_with_attachments(from_email, from_password, to_email, subject, body, pdf_files,
                                from_name, message_id=None, in_reply_to=None):
    """Send a single email with PDF attachments over its own SMTP connection."""
    try:
        msg = build_email_message(
            from_email, from_name, to_email, subject, body, pdf_files,
            message_id=message_id, in_reply_to=in_reply_to,
        )
        server = open_smtp_connection(from_email, from_password)
        try:
            server.send_message(msg, from_email, [to_email])
        finally:
            server.quit()
        return True

    except Exception as e:
        print(f"Error sending email with attachments: {str(e)}")
        traceback.print_exc()
        return False


def send_emails_over_connection(from_email, from_password, from_name, jobs, delay_seconds=0.3):
    """
    Send multiple emails reusing a single SMTP connection (one login instead of one per email).
    `jobs` is a list of dicts with keys: to_email, subject, body, pdf_files (plus any extra
    caller-tracking keys, which are passed through untouched).
    Returns a list of (job, success, error_message) tuples in the same order as `jobs`.
    """
    if not jobs:
        return []

    sender = SmtpSender(from_email, from_password, from_name)
    try:
        sender.connect()
    except Exception as e:
        print(f"Error opening SMTP connection: {str(e)}")
        return [(job, False, f"SMTP login failed: {str(e)}") for job in jobs]

    results = []
    try:
        for idx, job in enumerate(jobs):
            try:
                sender.send(job)
                results.append((job, True, None))
            except Exception as e:
                print(f"Error sending to {job['to_email']}: {str(e)}")
                results.append((job, False, str(e)))

            # Small pacing delay to stay friendly with Gmail's rate limits, not a full batch stall
            if delay_seconds and idx < len(jobs) - 1:
                time.sleep(delay_seconds)
    finally:
        sender.close()

    return results


ATTACHMENT_SLOTS = threading.BoundedSemaphore(max(1, int(os.getenv('OUTREACH_ATTACHMENT_SLOTS', '3'))))


class AmbiguousDelivery(smtplib.SMTPException):
    """The connection failed mid-message, so the provider may or may not have accepted it."""


class SmtpSender:
    """One authenticated SMTP connection reused across many sends.

    Used by send_emails_over_connection (whole list at once) and by the background
    outreach worker (one job at a time, committing between sends). A dropped connection
    is reopened once per message; a failed login is raised from connect() so callers can
    stop instead of hammering the provider with bad credentials.
    """

    IDLE_CHECK_AFTER_SECONDS = 20

    def __init__(self, from_email, from_password, from_name):
        self.from_email = from_email
        self.from_password = from_password
        self.from_name = from_name
        self.server = None
        self.last_used = 0.0

    def connect(self):
        self.close()
        self.server = open_smtp_connection(self.from_email, self.from_password)
        self.last_used = time.monotonic()

    def _ensure_live_connection(self):
        """Reopen a connection the provider closed while idle, before any message is handed over."""
        if self.server is None:
            self.connect()
        elif time.monotonic() - self.last_used > self.IDLE_CHECK_AFTER_SECONDS:
            try:
                self.server.noop()
            except (smtplib.SMTPException, OSError):
                self.connect()

    def send(self, job):
        """Send one job dict (to_email, subject, body, pdf_files, optional in_reply_to).

        A server answer (rejection, quota) is raised as is. A connection that dies or times out
        while the message is in flight raises AmbiguousDelivery and is never resent here, because
        the provider may already have accepted it.
        """
        # Each attachment message is a few MB in memory while it is built and flattened, so only
        # a few run at once per process no matter how many batches are active.
        if job["pdf_files"]:
            with ATTACHMENT_SLOTS:
                return self._build_and_send(job)
        return self._build_and_send(job)

    def _build_and_send(self, job):
        msg = build_email_message(
            self.from_email, self.from_name, job["to_email"], job["subject"], job["body"],
            job["pdf_files"], in_reply_to=job.get("in_reply_to"),
        )
        self._ensure_live_connection()
        try:
            self.server.send_message(msg, self.from_email, [job["to_email"]])
        except (smtplib.SMTPServerDisconnected, socket.timeout, ConnectionError, ssl.SSLError) as exc:
            raise AmbiguousDelivery(
                "The connection dropped while sending, so delivery is unconfirmed. "
                "Check your Sent mail before sending again.") from exc
        self.last_used = time.monotonic()
        job["message_id"] = msg["Message-ID"]
        return job["message_id"]

    def reset(self):
        """After a failed send, make the connection usable again or drop it so the next send reconnects."""
        try:
            self.server.rset()
        except Exception:
            self.close()

    def close(self):
        server, self.server = self.server, None
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


def advance_school_stage(school):
    """Move a school to 'contacted' after a send, but never downgrade a later stage."""
    if school.status in (None, '', 'pending'):
        school.status = 'contacted'


def record_outbound_message(record, message_id, subject, kind):
    if message_id:
        db.session.add(SentMessage(
            sent_email=record, message_id=message_id, subject=subject, kind=kind,
        ))

FOLLOWUP_WAIT_DAYS = 7
FOLLOWUP_MAX_AGE_DAYS = MAIL_SYNC_LOOKBACK_DAYS
FOLLOWUP_SUBJECT = "Follow-Up: PSA Programs"


def followup_due_at(email_record):
    if not email_record.sent_at:
        return None
    return email_record.sent_at + timedelta(days=FOLLOWUP_WAIT_DAYS)


def followup_eligibility_error(email_record):
    """Use the same rule for the queue, preview, and final send."""
    if email_record.responded:
        return "This school has already responded"
    if email_record.followup_sent:
        return "Follow-up already sent"
    linked = db.session.get(SalesSchool, email_record.sales_school_id) if email_record.sales_school_id else None
    if linked and linked.status in FINISHED_STAGES:
        return "This school is a client or has closed out; no follow-up is needed"
    if email_record.sent_at and email_record.sent_at < utc_now() - timedelta(days=FOLLOWUP_MAX_AGE_DAYS):
        return "This email is too old for a follow-up; start a new conversation"
    due_at = followup_due_at(email_record)
    if due_at is None or utc_now() < due_at:
        return "Follow-up is due 7 days after the original email"
    return None


def user_mail_password(user):
    """Return the usable secret only at the SMTP/IMAP boundary."""
    return decrypt_password(user.email_password)


def followup_message(user, original_email):
    """Render the exact message used by both preview and SMTP send."""
    schools = SalesSchool.query.filter_by(
        school_name=original_email.school_name, user_id=user.id
    ).all()
    school = db.session.get(SalesSchool, original_email.sales_school_id) if original_email.sales_school_id else None
    if school is None:
        school = next(
            (item for item in schools if original_email.school_email in item.get_all_emails()),
            None,
        )
    if school and school.school_type == 'preschool':
        template = PRESCHOOL_FOLLOWUP_TEMPLATE
    elif school and school.school_type == 'private':
        template = PRIVATE_SCHOOL_FOLLOWUP_TEMPLATE
    else:
        template = ELEMENTARY_FOLLOWUP_TEMPLATE
    return render_email_text(
        template,
        school_name=original_email.school_name,
        user_name=user.name,
        user_email=user.email,
    )


@app.route("/api/followup-preview/<int:email_id>", methods=["GET"])
@jwt_required()
def followup_preview(email_id):
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    original_email = SentEmail.query.filter_by(id=email_id, user_id=user_id).first()
    if not user or not original_email:
        return jsonify({"error": "Email not found"}), 404
    error = followup_eligibility_error(original_email)
    if error:
        return jsonify({"error": error}), 409
    if not mail_sync_status(user.id)["ready"]:
        return jsonify({"error": "Check your inbox before reviewing follow-ups"}), 409
    return jsonify({
        "email_id": original_email.id,
        "school_name": original_email.school_name,
        "to_email": original_email.school_email,
        "subject": FOLLOWUP_SUBJECT,
        "body": followup_message(user, original_email),
        "sent_at": original_email.sent_at.isoformat(),
        "due_at": followup_due_at(original_email).isoformat(),
    })


@app.route("/api/send-followup", methods=["POST"])
@jwt_required()
def send_followup():
    data = request.get_json(silent=True) or {}
    email_id = data.get("email_id")
    
    if not email_id:
        return jsonify({"error": "Missing email_id"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.email_password:
        return jsonify({"error": "User not connected with email"}), 400

    # Get the original email record
    # Hold this row until the send result is recorded so a second request cannot
    # send the same follow-up while the first SMTP call is still in flight.
    original_email = SentEmail.query.filter_by(id=email_id, user_id=user_id).with_for_update().first()
    if not original_email:
        return jsonify({"error": "Email not found"}), 404

    error = followup_eligibility_error(original_email)
    if error:
        return jsonify({"error": error}), 409
    if not mail_sync_status(user.id)["ready"]:
        return jsonify({"error": "Check your inbox before sending follow-ups"}), 409

    followup_body = followup_message(user, original_email)

    password = user_mail_password(user)
    message_id = email.utils.make_msgid(domain=user.email.rsplit('@', 1)[-1])
    latest = SentMessage.query.filter_by(sent_email_id=original_email.id).order_by(SentMessage.sent_at.desc()).first()
    try:
        # Use the same send_email_with_attachments function that works for regular emails
        success = send_email_with_attachments(
            from_email=user.email,
            from_password=password,
            to_email=original_email.school_email,
            subject=FOLLOWUP_SUBJECT,
            body=followup_body,
            pdf_files=[],  # No attachments for follow-ups
            from_name=user.name,
            message_id=message_id,
            in_reply_to=latest.message_id if latest else None,
        )
        
        if success:
            original_email.followup_sent = True
            record_outbound_message(original_email, message_id, FOLLOWUP_SUBJECT, "followup")
            db.session.commit()
            return jsonify({"status": "follow-up sent"})
        else:
            return jsonify({"error": "Failed to send follow-up email"}), 500
            
    except Exception as e:
        print(f"Error sending follow-up email: {str(e)}")
        return jsonify({"error": f"Failed to send follow-up: {str(e)}"}), 500

@app.route("/api/mark-responded", methods=["POST"])
@jwt_required()
def mark_responded():
    data = request.get_json()
    email_id = data.get("email_id")
    responded = data.get("responded", True)
    
    if not email_id:
        return jsonify({"error": "Missing email_id"}), 400

    user_id = get_jwt_identity()
    email_record = SentEmail.query.filter_by(id=email_id, user_id=user_id).first()
    
    if not email_record:
        return jsonify({"error": "Email not found"}), 404

    email_record.responded = responded
    if responded and email_record.sales_school_id:
        school = db.session.get(SalesSchool, email_record.sales_school_id)
        if school and school.status in ('pending', 'contacted'):
            school.status = 'replied'
    db.session.commit()
    return jsonify({"status": "updated"})

@app.route("/api/sent-emails", methods=["GET"])
@jwt_required()
def get_sent_emails():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # If admin, return all sent emails; otherwise, return only user's emails
    if user.admin and request.args.get('scope') != 'mine':
        emails = SentEmail.query.all()
    else:
        emails = SentEmail.query.filter_by(user_id=user_id).all()
    
    # Get all email data with last sent date calculation
    email_data = []
    for email in emails:
        # Calculate days since sent
        days_ago = (datetime.utcnow() - email.sent_at).days
        
        # Get user name for admin view
        sender_user = User.query.get(email.user_id) if email.user_id else None
        
        due_at = followup_due_at(email)
        email_data.append({
            "id": email.id,
            "school_name": email.school_name,
            "school_email": email.school_email,
            "sales_school_id": email.sales_school_id,
            "sent_at": email.sent_at.isoformat(),
            "sent_at_formatted": email.sent_at.strftime("%b %d, %Y"),
            "days_ago": days_ago,
            "followup_due_at": due_at.isoformat() if due_at else None,
            "followup_eligible": email.user_id == user.id and followup_eligibility_error(email) is None,
            "responded": email.responded,
            "followup_sent": email.followup_sent,
            "has_reply_content": bool(email.reply_content),
            "is_mine": email.user_id == user.id,
            "user_name": sender_user.name if sender_user else "Unknown"
        })
    
    return jsonify(email_data)

@app.route("/api/delete-sent-email", methods=["DELETE"])
@jwt_required()
def delete_sent_email():
    data = request.get_json()
    email_id = data.get("email_id")
    
    if not email_id:
        return jsonify({"error": "Missing email_id"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Find the email record - admins can delete any, users only their own
    if user.admin:
        email_record = SentEmail.query.get(email_id)
    else:
        email_record = SentEmail.query.filter_by(id=email_id, user_id=user_id).first()
    
    if not email_record:
        return jsonify({"error": "Email record not found"}), 404

    try:
        db.session.delete(email_record)
        db.session.commit()
        return jsonify({"status": "Email record deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/email-reply/<int:email_id>", methods=["GET"])
@jwt_required()
def get_email_reply(email_id):
    """Get the reply content for a specific email"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Find the email record - admins can view any, users only their own
    if user.admin:
        email_record = SentEmail.query.get(email_id)
    else:
        email_record = SentEmail.query.filter_by(id=email_id, user_id=user_id).first()
    
    if not email_record:
        return jsonify({"error": "Email record not found"}), 404
    
    if not email_record.responded or not email_record.reply_content:
        return jsonify({"error": "No reply found for this email"}), 404
    
    return jsonify({
        "id": email_record.id,
        "school_name": email_record.school_name,
        "school_email": email_record.school_email,
        "sent_at": email_record.sent_at,
        "reply_content": email_record.reply_content,
        "reply_subject": email_record.reply_subject,
        "reply_date": email_record.reply_date,
        "reply_sender": email_record.reply_sender
    })

@app.route("/api/email-reply-chain/<int:email_id>", methods=["GET"])
@jwt_required()
def get_email_reply_chain(email_id):
    """Get all replies for a specific email (conversation chain)"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Find the email record - admins can view any, users only their own
    if user.admin:
        email_record = SentEmail.query.get(email_id)
    else:
        email_record = SentEmail.query.filter_by(id=email_id, user_id=user_id).first()
    
    if not email_record:
        return jsonify({"error": "Email record not found"}), 404
    
    # Get all replies for this email, ordered by date
    replies = EmailReply.query.filter_by(sent_email_id=email_id).order_by(EmailReply.reply_date.asc()).all()
    
    return jsonify({
        "id": email_record.id,
        "school_name": email_record.school_name,
        "school_email": email_record.school_email,
        "sent_at": email_record.sent_at,
        "reply_count": len(replies),
        "last_reply_date": email_record.last_reply_date,
        "reply_content": email_record.reply_content,
        "replies": [
            {
                "id": reply.id,
                "reply_content": reply.reply_content,
                "reply_subject": reply.reply_subject,
                "reply_date": reply.reply_date,
                "reply_sender": reply.reply_sender,
                "created_at": reply.created_at
            }
            for reply in replies
        ]
    })

# ====================================================
# API ENDPOINTS - SCHOOL FINDER
# ====================================================

# The finder (/api/find-schools, /details, /save-batch) lives in finder.py and is
# registered with the other route modules at the bottom of this file.

# ====================================================
# API ENDPOINTS - ROUTE PLANNING
# ====================================================

@app.route("/api/route-plan", methods=["POST"])
@jwt_required()
def route_plan():
    """Suggest a visit order in bounded time; distance is geographic, not driving."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='Supply schools and a starting address'), 400
    schools = data.get('schools')
    if not isinstance(schools, list) or not 2 <= len(schools) <= 25:
        return jsonify(error='Select between 2 and 25 schools'), 400
    for school in schools:
        if not isinstance(school, dict) or not isinstance(school.get('place_id'), str) or not school['place_id']:
            return jsonify(error='Each school needs a place identifier'), 400
        for key, bound in (('lat', 90), ('lng', 180)):
            value = school.get(key)
            if type(value) not in (float, int) or not isfinite(value) or abs(value) > bound:
                return jsonify(error='Each school needs valid coordinates'), 400
    if len({school['place_id'] for school in schools}) != len(schools):
        return jsonify(error='Select each school only once'), 400
    address = data.get('start_address')
    if not isinstance(address, str) or not address.strip() or len(address) > 500:
        return jsonify(error='Enter a starting address'), 400
    lat, lng = geocode_address(address)
    if lat is None or lng is None:
        return jsonify(error='Starting address not found'), 404
    from .routing import order_visits
    route, distance = order_visits(schools, (lat, lng), haversine)
    return jsonify(route=route, method='geographic_distance', distance_km=round(distance, 2))

# ====================================================
# API ENDPOINTS - MAP VISUALIZATION
# ====================================================

@app.route("/api/map-schools", methods=["GET"])
@jwt_required()
def map_schools():
    saved = db.session.get(MapSnapshot, 1)
    return jsonify(json.loads(saved.data_json) if saved else {})


@app.route('/api/refresh-map-schools', methods=['POST'])
@jwt_required()
def refresh_map_schools():
    error = admin_access_error()
    if error:
        return error
    try:
        psa, happyfeet, elementary = split_sheet_schools(load_PSA_school_sheet())
    except Exception:
        app.logger.exception('Could not load map source')
        return jsonify(error='Map source is temporarily unavailable. Your saved map is unchanged.'), 503
    groups = {'psa': psa, 'happyfeet': happyfeet, 'elementary': elementary, 'rec': REC_SITES}
    keys = {normalize_name(item['address']) for points in groups.values() for item in points}
    cached = {row.address_key: row for row in GeocodedAddress.query.filter(GeocodedAddress.address_key.in_(keys)).all()}
    data = {key: [] for key in groups}
    started, processed, remaining, failed, total = time.monotonic(), 0, 0, 0, 0
    attempted = {}
    for group, points in groups.items():
        for item in points:
            total += 1
            key = normalize_name(item['address'])
            entry = cached.get(key)
            if geocode_cache_valid(entry):
                lat, lng = entry.lat, entry.lng
            elif key in attempted:
                lat, lng = attempted[key]
            elif processed < 10 and time.monotonic() - started < 20:
                lat, lng = geocode_address(item['address'])
                attempted[key] = (lat, lng)
                processed += 1
            else:
                remaining += 1
                continue
            if lat is None or lng is None:
                failed += 1
                continue
            data[group].append({'name': item['name'], 'address': item['address'], 'type': group, 'lat': lat, 'lng': lng})
    saved = db.session.get(MapSnapshot, 1)
    if saved is None:
        saved = MapSnapshot(id=1)
        db.session.add(saved)
    saved.data_json = json.dumps(data)
    saved.updated_at = utc_now()
    db.session.commit()
    return jsonify(message='Map refresh batch complete', total=total, remaining=remaining,
                   processed=processed, failed=failed, mapped=sum(len(points) for points in data.values()))


@app.route('/api/team-stats', methods=['GET'])
@jwt_required()
def get_team_stats():
    """Get all team members with their statistics"""
    try:
        current_user = get_jwt_identity()
        
        # Get all users
        users = User.query.all()  # Use SQLAlchemy ORM instead of raw SQL
        
        team_stats = []
        
        for user in users:
            # Count schools for this user - use correct table name 'sales_schools'
            school_count = SalesSchool.query.filter_by(user_id=user.id).count()
            
            # Count emails for this user
            email_count = SentEmail.query.filter_by(user_id=user.id).count()
            
            team_stats.append({
                'name': user.name,
                'email': user.email,
                'phone': user.phone or 'Not provided',
                'role': 'Administrator' if user.admin else 'Sales Associate',
                'totalSchools': school_count,
                'totalEmails': email_count
            })
        
        return jsonify(team_stats)
        
    except Exception as e:
        print(f"Error in team-stats: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/all-schools', methods=['GET'])
@jwt_required()
def get_all_schools():
    """Get all schools with user information (for fallback team stats)"""
    error = admin_access_error()
    if error:
        return error
    try:
        # Use SQLAlchemy ORM with joins
        schools = db.session.query(SalesSchool, User).outerjoin(User, SalesSchool.user_id == User.id).all()
        
        school_list = []
        for school, user in schools:
            school_list.append({
                'id': school.id,
                'school_name': school.school_name,
                'contact_name': school.contact_name,
                'email': school.email,
                'phone': school.phone,
                'address': school.address,
                'school_type': school.school_type,
                'status': school.status,
                'user_id': school.user_id,
                'user_name': user.name if user else None,
                'user_email': user.email if user else None,
                'user_phone': user.phone if user else None
            })
        
        return jsonify(school_list)
        
    except Exception as e:
        print(f"Error in all-schools: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/all-emails', methods=['GET'])
@jwt_required()
def get_all_emails():
    """Get all sent emails with user information (for fallback team stats)"""
    error = admin_access_error()
    if error:
        return error
    try:
        # Use SQLAlchemy ORM with joins
        emails = db.session.query(SentEmail, User).outerjoin(User, SentEmail.user_id == User.id).all()
        
        email_list = []
        for email, user in emails:
            email_list.append({
                'id': email.id,
                'school_name': email.school_name,
                'school_email': email.school_email,
                'sent_at': email.sent_at.isoformat() if email.sent_at else None,
                'responded': email.responded,
                'followup_sent': email.followup_sent,
                'user_id': email.user_id,
                'user_name': user.name if user else None,
                'user_email': user.email if user else None,
                'user_phone': user.phone if user else None
            })
        
        return jsonify(email_list)
        
    except Exception as e:
        print(f"Error in all-emails: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ====================================================
# API ENDPOINTS - CUSTOM REPLIES
# ====================================================

@app.route("/api/send-custom-reply", methods=["POST"])
@jwt_required()
def send_custom_reply():
    """Send a custom reply to a school"""
    data = request.get_json()
    email_id = data.get("email_id")
   
    to_email = data.get("to_email")
    subject = data.get("subject")
    message = data.get("message")
    
    if not all([email_id, to_email, subject, message]):
        return jsonify({"error": "Missing required fields"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.email_password:
        return jsonify({"error": "User or email settings not configured"}), 400

    # Replies must come from the original sender's mailbox so incoming mail
    # stays in the same employee's conversation.
    email_record = SentEmail.query.filter_by(id=email_id, user_id=user_id).first()
    
    if not email_record:
        return jsonify({"error": "Email record not found"}), 404

    password = user_mail_password(user)
    message_id = email.utils.make_msgid(domain=user.email.rsplit('@', 1)[-1])
    latest = SentMessage.query.filter_by(sent_email_id=email_record.id).order_by(SentMessage.sent_at.desc()).first()
    try:
        # Send the custom reply
        success = send_email_with_attachments(
            from_email=user.email,
            from_password=password,
            to_email=to_email,
            subject=subject,
            body=message,
            pdf_files=[],  # No attachments for replies
            from_name=user.name,
            message_id=message_id,
            in_reply_to=latest.message_id if latest else None,
        )
        
        if success:
            record_outbound_message(email_record, message_id, subject, "reply")
            db.session.commit()
            return jsonify({"status": "Custom reply sent successfully"})
        else:
            return jsonify({"error": "Failed to send custom reply"}), 500
            
    except Exception as e:
        print(f"Error sending custom reply: {str(e)}")
        return jsonify({"error": f"Failed to send custom reply: {str(e)}"}), 500

@app.route("/api/send-custom-email", methods=["POST"])
@jwt_required()
def send_custom_email():
    """Send a custom/freeform email to a school"""
    ALLOWED_PDFS = {
        "PSA TOTS seasonal flyer.pdf",
        "PSA TOTS year round flyer.pdf",
        "PSA TOTS Recommendation (Primrose School).pdf",
        "PSA After School.pdf",
        "PSA Recommendation (St. Theresa).pdf",
        "PSA Recommendation Letter (Madison Trust ES).pdf",
    }

    data = request.get_json()
    school_id = data.get("school_id")
    to_email = data.get("to_email")
    subject = data.get("subject")
    message = data.get("message")
    requested_pdfs = data.get("pdf_files", [])
    pdf_files = [p for p in requested_pdfs if p in ALLOWED_PDFS]

    if not all([school_id, to_email, subject, message]):
        return jsonify({"error": "Missing required fields"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user or not user.email_password:
        return jsonify({"error": "User or email settings not configured"}), 400

    school = SalesSchool.query.filter_by(id=school_id, user_id=user_id).first()

    if not school:
        return jsonify({"error": "School not found"}), 404

    if not isinstance(to_email, str) or to_email.strip().casefold() not in {
        item.strip().casefold() for item in school.get_all_emails()
    }:
        return jsonify({"error": "Choose a saved school contact"}), 400

    def apply_vars(text):
        return (text
            .replace('[school_name]', school.school_name or '')
            .replace('[contact_name]', school.contact_name or 'Director/Administrator')
            .replace('[user_name]', user.name or '')
            .replace('[user_email]', user.email or ''))

    password = user_mail_password(user)
    rendered_subject = apply_vars(subject)
    message_id = email.utils.make_msgid(domain=user.email.rsplit('@', 1)[-1])
    try:
        success = send_email_with_attachments(
            from_email=user.email,
            from_password=password,
            to_email=to_email,
            subject=rendered_subject,
            body=apply_vars(message),
            pdf_files=pdf_files,
            from_name=user.name,
            message_id=message_id,
        )

        if success:
            new_email = SentEmail(
                school_name=school.school_name,
                school_email=to_email,
                user_id=user_id,
                sales_school_id=school.id,
                responded=False,
                followup_sent=False
            )
            db.session.add(new_email)
            record_outbound_message(new_email, message_id, rendered_subject, "outreach")
            advance_school_stage(school)
            db.session.commit()
            return jsonify({"status": "Custom email sent successfully"})
        else:
            return jsonify({"error": "Failed to send email"}), 500

    except Exception as e:
        print(f"Error sending custom email: {str(e)}")
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500

@app.route("/api/send-custom-email-bulk", methods=["POST"])
@jwt_required()
def send_custom_email_bulk():
    """Send a custom email to multiple schools using the same batching logic as send_email"""
    ALLOWED_PDFS = {
        "PSA TOTS seasonal flyer.pdf",
        "PSA TOTS year round flyer.pdf",
        "PSA TOTS Recommendation (Primrose School).pdf",
        "PSA After School.pdf",
        "PSA Recommendation (St. Theresa).pdf",
        "PSA Recommendation Letter (Madison Trust ES).pdf",
    }

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='Supply an outreach request'), 400
    school_ids = data.get("school_ids", [])
    if (not isinstance(school_ids, list) or not 1 <= len(school_ids) <= 100
            or any(type(value) is not int or value < 1 for value in school_ids)):
        return jsonify(error='Select between 1 and 100 schools'), 400
    subject = data.get("subject")
    message = data.get("message")
    requested_pdfs = data.get("pdf_files", [])
    pdf_files = [p for p in requested_pdfs if p in ALLOWED_PDFS]

    if not school_ids or not subject or not message:
        return jsonify({"error": "Missing required fields"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user or not user.email_password:
        return jsonify({"error": "User or email settings not configured"}), 400

    schools = SalesSchool.query.filter(
        SalesSchool.id.in_(school_ids), SalesSchool.user_id == user_id
    ).all()
    if len(schools) != len(set(school_ids)):
        return jsonify({"error": "Send only to schools assigned to you"}), 403

    if not schools:
        return jsonify({"error": "No valid schools found"}), 400

    jobs = []
    for school in schools:
        def apply_vars(text, s=school):
            return (text
                .replace('[school_name]', s.school_name or '')
                .replace('[contact_name]', s.contact_name or 'Director/Administrator')
                .replace('[user_name]', user.name or '')
                .replace('[user_email]', user.email or ''))

        jobs.append({
            "school": school,
            "to_email": school.email,
            "subject": apply_vars(subject),
            "body": apply_vars(message),
            "pdf_files": pdf_files
        })

    # One login, one connection reused for every email in this request instead of one
    # SMTP connection per school (see send_emails_over_connection).
    results = send_emails_over_connection(user.email, user_mail_password(user), user.name, jobs)

    sent_count = 0
    errors = []

    for job, success, error in results:
        school = job["school"]
        if success:
            record = SentEmail(
                school_name=school.school_name,
                school_email=job["to_email"],
                user_id=user_id,
                sales_school_id=school.id,
                responded=False,
                followup_sent=False
            )
            db.session.add(record)
            record_outbound_message(record, job.get("message_id"), job["subject"], "outreach")
            advance_school_stage(school)
            sent_count += 1
        else:
            errors.append(f"Failed to send to {school.school_name}: {error}")

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Commit error: {str(e)}")

    return jsonify({
        "status": f"{sent_count} emails sent successfully" if sent_count > 0 else "Failed to send emails",
        "sent_count": sent_count,
        "errors": errors
    })

# ====================================================
# APPLICATION STARTUP
# ====================================================

from .crm import register_crm_routes
register_crm_routes(app, db, User, SalesSchool, SentEmail, SalesTask, SchoolActivity, school_dict, School)


class _FinderHooks:
    """Late-bound lookups so the route modules always call the current helpers."""
    normalize_name = staticmethod(lambda text: normalize_name(text))
    haversine = staticmethod(lambda *args: haversine(*args))
    geocode = staticmethod(lambda address: geocode_address(address))
    google_key = staticmethod(lambda: GOOGLE_API_KEY)
    school_conflict = staticmethod(lambda *args: school_conflict(*args))
    valid_email = staticmethod(lambda value: valid_email(value))
    sleep = staticmethod(lambda seconds: time.sleep(seconds))

    @staticmethod
    def partner_names():
        groups = split_sheet_schools(load_PSA_school_sheet())
        names = {normalize_name(school["name"]) for group in groups for school in group}
        names.discard('')
        return names


from .portfolio import register_portfolio_routes  # noqa: E402
from .finder import register_finder_routes  # noqa: E402
register_portfolio_routes(app, db, User, SalesSchool, SchoolActivity, SentEmail, GeocodedAddress, _FinderHooks)
register_finder_routes(app, db, SalesSchool, User, _FinderHooks)

import sys as _sys
from .outreach import register_outreach_routes
register_outreach_routes(app, db, _sys.modules[__name__])

from .taskbar_sync import register_taskbar_sync  # noqa: E402
register_taskbar_sync(app, db, User, SalesTask)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

