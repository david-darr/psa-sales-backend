# ====================================================
# IMPORTS & EXTERNAL LIBRARIES
# ====================================================

import os
import requests
import re
import json
import time
import imaplib
import email
import ssl
import pytz
import atexit
import logging
from itertools import permutations
from math import radians, cos, sin, sqrt, atan2
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
import smtplib

# Flask & Extensions
from flask import Flask, request, jsonify, render_template_string
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
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
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'postgresql://postgres.dlnfvtudzyyabixedniz:Pandaplayz6!@aws-0-us-east-1.pooler.supabase.com:6543/postgres'
)
db = SQLAlchemy(app)

# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
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
    email_password = db.Column(db.String, nullable=True)  # App password for Gmail
    smtp_server = db.Column(db.String, default='smtp.gmail.com')
    smtp_port = db.Column(db.Integer, default=587)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    user = db.relationship('User', backref=db.backref('sales_schools', lazy=True))
    
    def get_all_emails(self):
        """Get all emails for this school (primary + additional)"""
        emails = [self.email]
        if self.additional_emails:
            try:
                additional = json.loads(self.additional_emails)
                if isinstance(additional, list):
                    emails.extend([email.strip() for email in additional if email.strip()])
            except (json.JSONDecodeError, TypeError):
                pass
        return emails
    
    def set_additional_emails(self, email_list):
        """Set additional emails from a list"""
        if email_list and isinstance(email_list, list):
            # Filter out empty strings and the primary email
            filtered_emails = [email.strip() for email in email_list if email.strip() and email.strip() != self.email]
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
    Splits sheet rows into PSA Preschools and Happy Feet schools based on indicator rows.
    PSA Preschools: column 2 is name, column 14 is address.
    Happy Feet: column 2 is name, column 15 is address.
    """
    psa_preschools = []
    happy_feet = []
    mode = None  # None, "psa", "happyfeet"
    
    for row in sheet_rows:
        if len(row) < 15:
            continue
        indicator = str(row[1]).strip().lower()
        if indicator == "northern virginia (psa)":
            mode = "psa"
            continue
        elif indicator == "northern virginia (happyfeet)":
            mode = "happyfeet"
            continue
        
        if mode == "psa":
            name = str(row[1]).strip()
            address = str(row[13]).strip()
            if not name or not address or name.lower() in {"school name", "elementary", "preschool"}:
                continue
            psa_preschools.append({"name": name, "address": address})
        elif mode == "happyfeet":
            name = str(row[1]).strip()
            address = str(row[14]).strip()
            if not name or not address or name.lower() in {"school name", "elementary", "preschool"}:
                continue
            happy_feet.append({"name": name, "address": address})
    
    return psa_preschools, happy_feet

# Initialize cached sheet data
psa_preschools, happy_feet = split_sheet_schools(load_PSA_school_sheet())

# Constants
REC_SITES = [
    {"name": "Hanson Park", "address": "22831 Hanson Park Dr, Aldie, VA 20105"},
    {"name": "Heron Overlook", "address": "20550 Heron overlook Plz, Ashburn, VA 20147"}
]

GENERIC_NAMES = {"elementary", "preschool", "school name", "elementary school"}
MAP_SCHOOL_CACHE = {}

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

def geocode_address(address):
    """Geocode an address using HERE API."""
    if not address:
        return None, None
    HERE_API_KEY = os.getenv("HERE_API_KEY")
    url = "https://geocode.search.hereapi.com/v1/geocode"
    params = {"q": address, "apiKey": HERE_API_KEY, "limit": 1}
    resp = requests.get(url, params=params).json()
    items = resp.get("items")
    if items:
        position = items[0]["position"]
        return position["lat"], position["lng"]
    return None, None

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

def check_email_replies():
    """Check for email replies and update the database (background version)"""
    with app.app_context():
        start_time = datetime.utcnow()
        print(f"=== AUTOMATIC EMAIL REPLY CHECK STARTED at {start_time} ===")
        
        try:
            # Get users with email configurations (limit to prevent timeout)
            users_with_emails = User.query.filter(
                User.email_password.isnot(None),
                User.id.in_(db.session.query(SentEmail.user_id).distinct())
            ).limit(2).all()  # Limit to 2 users for background processing
            
            print(f"Found {len(users_with_emails)} users with email configurations")
            
            total_replies_found = 0
            
            for user in users_with_emails:
                try:
                    print(f"Checking emails for user: {user.email}")
                    # Use limited version for background processing too
                    new_replies = check_user_email_replies_limited(user, max_emails_to_check=10, max_replies_to_process=5)
                    total_replies_found += new_replies
                    print(f"Found {new_replies} new replies for {user.email}")
                except Exception as e:
                    print(f"Error checking emails for user {user.email}: {str(e)}")
                    continue
            
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            print(f"=== AUTOMATIC EMAIL REPLY CHECK COMPLETED at {end_time} ===")
            print(f"Duration: {duration:.2f} seconds")
            print(f"Total new replies found: {total_replies_found}")
            
        except Exception as e:
            print(f"ERROR in automatic email check: {str(e)}")
            traceback.print_exc()

def check_user_email_replies(user):
    """Check email replies for a specific user and store reply content"""
    try:
        print(f"DEBUG: Starting email check for {user.email}")
        
        # Connect to Gmail IMAP
        context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993, ssl_context=context)
        mail.login(user.email, user.email_password)
        
        # Select inbox
        mail.select("inbox")
        
        # Get emails from the last 7 days only
        since_date = (datetime.utcnow() - timedelta(days=7)).strftime("%d-%b-%Y")
        print(f"DEBUG: Searching for emails since {since_date}")
        
        # Search for emails with "Re:" in subject from the last 7 days
        status, messages = mail.search(None, f'(SINCE {since_date}) (SUBJECT "Re:")')
        
        if status == "OK":
            email_ids = messages[0].split()
            print(f"DEBUG: Found {len(email_ids)} emails with 'Re:' in subject")
            
            # Get sent emails for this user that haven't been marked as responded
            sent_emails = SentEmail.query.filter_by(
                user_id=user.id, 
                responded=False
            ).all()
            
            print(f"DEBUG: Found {len(sent_emails)} unresponded sent emails")
            
            # Create a dictionary of school email addresses for quick lookup
            school_emails = {}
            for sent_email in sent_emails:
                school_emails[sent_email.school_email.lower()] = sent_email
                print(f"DEBUG: Watching for replies from: {sent_email.school_email}")
            
            if not school_emails:
                print("DEBUG: No unresponded emails to check for replies")
                mail.close()
                mail.logout()
                return
            
            replies_found = 0
            
            # Check each "Re:" email
            for email_id in email_ids:
                try:
                    # Fetch the email
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    
                    if status == "OK":
                        # Parse the email
                        email_message = email.message_from_bytes(msg_data[0][1])
                        
                        # Get sender email address
                        from_address = email_message.get('From', '')
                        sender_email = extract_email_from_string(from_address).lower()
                        
                        # Get subject and reply date
                        subject = email_message.get('Subject', '')
                        reply_date_str = email_message.get('Date', '')
                        
                        # Parse reply date
                        reply_date = None
                        if reply_date_str:
                            try:
                                # Parse email date format
                                reply_date = email.utils.parsedate_to_datetime(reply_date_str)
                                # Convert to UTC if timezone aware
                                if reply_date.tzinfo:
                                    reply_date = reply_date.astimezone(timezone.utc).replace(tzinfo=None)
                            except Exception as e:
                                print(f"DEBUG: Could not parse date '{reply_date_str}': {e}")
                                reply_date = datetime.utcnow()
                        
                        print(f"DEBUG: Checking reply from {sender_email} with subject '{subject}'")
                        
                        # Extract email body
                        body_content = ""
                        if email_message.is_multipart():
                            for part in email_message.walk():
                                if part.get_content_type() == "text/plain":
                                    try:
                                        body_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                        break
                                    except Exception as e:
                                        print(f"DEBUG: Error decoding email part: {e}")
                        else:
                            try:
                                body_content = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')
                            except Exception as e:
                                print(f"DEBUG: Error decoding email body: {e}")
                        
                        # Clean up body content (remove excessive line breaks, etc.)
                        if body_content:
                            # Remove excessive whitespace but preserve structure
                            body_content = re.sub(r'\n\s*\n\s*\n', '\n\n', body_content)
                            body_content = body_content.strip()
                            # Limit length to prevent database issues
                            if len(body_content) > 10000:
                                body_content = body_content[:10000] + "\n\n[Content truncated...]"
                        
                        # Check if this is a reply to one of our sent emails
                        if sender_email in school_emails:
                            sent_email_record = school_emails[sender_email]
                            print(f"DEBUG: ✅ Found reply from {sent_email_record.school_name}!")
                            
                            # Update the sent email record with reply information
                            sent_email_record.responded = True
                            sent_email_record.reply_content = body_content
                            sent_email_record.reply_subject = subject
                            sent_email_record.reply_date = reply_date or datetime.utcnow()
                            sent_email_record.reply_sender = from_address
                            
                            replies_found += 1
                            
                            # Remove from dict so we don't check it again
                            del school_emails[sender_email]
                        
                except Exception as e:
                    print(f"DEBUG: Error processing email {email_id}: {str(e)}")
                    continue
            
            if replies_found > 0:
                db.session.commit()
                print(f"DEBUG: ✅ Successfully marked {replies_found} replies with content stored")
            else:
                print(f"DEBUG: ❌ No replies found from watched schools")
        else:
            print(f"DEBUG: Email search failed with status: {status}")
        
        mail.close()
        mail.logout()
        
    except Exception as e:
        print(f"DEBUG: Error connecting to email for {user.email}: {str(e)}")
        traceback.print_exc()

def check_user_email_replies_limited(user, max_emails_to_check=20, max_replies_to_process=10):
    """Check email replies for a specific user with limits to prevent timeout - supports multiple replies"""
    try:
        print(f"DEBUG: Starting LIMITED email check for {user.email}")
        
        # Connect to Gmail IMAP with timeout
        context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993, ssl_context=context)
        mail.login(user.email, user.email_password)
        
        # Select inbox
        mail.select("inbox")
        
        # Get emails from the last 7 days (increased from 3 to catch more replies)
        since_date = (datetime.utcnow() - timedelta(days=7)).strftime("%d-%b-%Y")
        print(f"DEBUG: Searching for emails since {since_date}")
        
        # Search for emails with "Re:" in subject from the last 7 days
        status, messages = mail.search(None, f'(SINCE {since_date}) (SUBJECT "Re:")')
        
        if status == "OK":
            email_ids = messages[0].split()
            print(f"DEBUG: Found {len(email_ids)} emails with 'Re:' in subject")
            
            # LIMIT: Only check first 20 emails to prevent timeout
            email_ids = email_ids[:max_emails_to_check]
            print(f"DEBUG: Limited to first {len(email_ids)} emails for processing")
            
            # Get ALL sent emails for this user (including already responded ones)
            # This is the key change - we now check all emails, not just unresponded ones
            sent_emails = SentEmail.query.filter(
                SentEmail.user_id == user.id,
                SentEmail.sent_at >= datetime.utcnow() - timedelta(days=60)  # Last 60 days
            ).all()
            
            print(f"DEBUG: Found {len(sent_emails)} sent emails (including already responded)")
            
            # Create a dictionary of school email addresses for lookup
            school_emails = {}
            for sent_email in sent_emails:
                school_emails[sent_email.school_email.lower()] = sent_email
            
            if not school_emails:
                print("DEBUG: No sent emails to check for replies")
                mail.close()
                mail.logout()
                return 0
            
            # Get existing reply message IDs to avoid duplicates
            existing_message_ids = set()
            existing_replies = EmailReply.query.join(SentEmail).filter(
                SentEmail.user_id == user.id,
                EmailReply.reply_message_id.isnot(None)
            ).all()
            
            for reply in existing_replies:
                if reply.reply_message_id:
                    existing_message_ids.add(reply.reply_message_id)
            
            print(f"DEBUG: Found {len(existing_message_ids)} existing reply message IDs")
            
            new_replies_found = 0
            
            # Check each "Re:" email
            for idx, email_id in enumerate(email_ids):
                # TIMEOUT PROTECTION
                if new_replies_found >= max_replies_to_process:
                    print(f"DEBUG: Reached limit of {max_replies_to_process} new replies, stopping")
                    break
                
                try:
                    # Fetch the email
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    
                    if status == "OK":
                        # Parse the email
                        email_message = email.message_from_bytes(msg_data[0][1])
                        
                        # Get message ID to avoid duplicates
                        message_id = email_message.get('Message-ID', '')
                        
                        # Skip if we've already processed this exact message
                        if message_id and message_id in existing_message_ids:
                            print(f"DEBUG: Skipping duplicate message ID: {message_id}")
                            continue
                        
                        # Get sender email address
                        from_address = email_message.get('From', '')
                        sender_email = extract_email_from_string(from_address).lower()
                        
                        # Quick check if this sender is in our watch list
                        if sender_email not in school_emails:
                            continue
                        
                        print(f"DEBUG: ✅ MATCH FOUND! Processing reply from {sender_email}")
                        
                        # Get email details
                        subject = email_message.get('Subject', '')
                        reply_date_str = email_message.get('Date', '')
                        
                        # Parse reply date
                        reply_date = None
                        if reply_date_str:
                            try:
                                reply_date = email.utils.parsedate_to_datetime(reply_date_str)
                                if reply_date.tzinfo:
                                    reply_date = reply_date.astimezone(timezone.utc).replace(tzinfo=None)
                            except Exception as e:
                                print(f"DEBUG: Could not parse date '{reply_date_str}': {e}")
                                reply_date = datetime.utcnow()
                        
                        # Extract email body
                        body_content = ""
                        if email_message.is_multipart():
                            for part in email_message.walk():
                                if part.get_content_type() == "text/plain":
                                    try:
                                        body_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                        break
                                    except Exception as e:
                                        print(f"DEBUG: Error decoding email part: {e}")
                        else:
                            try:
                                body_content = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')
                            except Exception as e:
                                print(f"DEBUG: Error decoding email body: {e}")
                        
                        # Clean up body content
                        if body_content:
                            body_content = re.sub(r'\n\s*\n\s*\n', '\n\n', body_content)
                            body_content = body_content.strip()
                            if len(body_content) > 8000:
                                body_content = body_content[:8000] + "\n\n[Content truncated...]"
                        
                        # Get the sent email record
                        sent_email_record = school_emails[sender_email]
                        
                        # Create new reply record
                        new_reply = EmailReply(
                            sent_email_id=sent_email_record.id,
                            reply_content=body_content,
                            reply_subject=subject,
                            reply_date=reply_date or datetime.utcnow(),
                            reply_sender=from_address,
                            reply_message_id=message_id
                        )
                        
                        db.session.add(new_reply)
                        
                        # Update the sent email record
                        sent_email_record.responded = True
                        sent_email_record.reply_count = (sent_email_record.reply_count or 0) + 1
                        sent_email_record.last_reply_date = reply_date or datetime.utcnow()
                        
                        # Keep the first reply in the old fields for backward compatibility
                        if sent_email_record.reply_count == 1:
                            sent_email_record.reply_content = body_content
                            sent_email_record.reply_subject = subject
                            sent_email_record.reply_date = reply_date or datetime.utcnow()
                            sent_email_record.reply_sender = from_address
                        
                        new_replies_found += 1
                        print(f"DEBUG: ✅ Reply #{new_replies_found} processed from {sent_email_record.school_name} (Total replies: {sent_email_record.reply_count})")
                        
                        # Add to existing message IDs to avoid processing duplicates in this session
                        if message_id:
                            existing_message_ids.add(message_id)
                        
                        # COMMIT IMMEDIATELY to avoid losing progress
                        try:
                            db.session.commit()
                        except Exception as commit_error:
                            print(f"DEBUG: Commit error: {commit_error}")
                            db.session.rollback()
                        
                except Exception as e:
                    print(f"DEBUG: Error processing email {email_id}: {str(e)}")
                    continue
            
            print(f"DEBUG: ✅ Successfully processed {new_replies_found} new replies")
        else:
            print(f"DEBUG: Email search failed with status: {status}")
        
        mail.close()
        mail.logout()
        return new_replies_found
        
    except Exception as e:
        print(f"DEBUG: Error in limited email check for {user.email}: {str(e)}")
        traceback.print_exc()
        return 0

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
scheduler_started = start_scheduler()
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
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    phone = data.get("phone")
    password = data.get("password")
    
    if not all([name, email, password]):
        return jsonify({"error": "Missing required fields"}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 400
    
    # Save to database
    user = User(name=name, email=email, phone=phone)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    return jsonify({"message": "User registered successfully"})

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
                "admin": user.admin
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
        "admin": user.admin
    })

# ====================================================
# API ENDPOINTS - EMAIL SETTINGS
# ====================================================

@app.route("/api/email-settings", methods=["POST"])
@jwt_required()
def save_email_settings():
    data = request.get_json()
    email_password = data.get("email_password")
    
    if not email_password:
        return jsonify({"error": "Email password required"}), 400
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Save encrypted email password (you might want to encrypt this)
    user.email_password = email_password
    db.session.commit()
    
    return jsonify({"message": "Email settings saved"})

@app.route("/api/check-email-replies", methods=["POST"])
@jwt_required()
def manual_check_email_replies():
    """Manually trigger email reply checking with timeout protection"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if not user.email_password:
        return jsonify({"error": "Email settings not configured"}), 400
    
    try:
        if user.admin:
            # Admin can check all emails - but limit to prevent timeout
            users_to_check = User.query.filter(
                User.email_password.isnot(None),
                User.id.in_(db.session.query(SentEmail.user_id).distinct())
            ).limit(3).all()  # Limit to 3 users max for manual check
            
            total_checked = 0
            for check_user in users_to_check:
                replies_found = check_user_email_replies_limited(check_user)
                total_checked += replies_found
                
            return jsonify({
                "status": f"Checked {len(users_to_check)} users, found {total_checked} new replies",
                "message": "Manual check completed (limited to prevent timeout)"
            })
        else:
            # Regular user can only check their own
            replies_found = check_user_email_replies_limited(user)
            return jsonify({
                "status": f"Found {replies_found} new replies for your account",
                "message": "Email check completed"
            })
    except Exception as e:
        print(f"Error in manual email check: {str(e)}")
        return jsonify({"error": f"Failed to check emails: {str(e)}"}), 500

# ====================================================
# API ENDPOINTS - SCHOOL MANAGEMENT
# ====================================================

@app.route("/api/add-school", methods=["POST"])
@jwt_required()
def add_school():
    data = request.get_json()
    school_name = data.get("school_name")
    email = data.get("email")
    additional_emails = data.get("additional_emails", [])  # New field
    contact_name = data.get("contact_name")
    phone = data.get("phone")
    address = data.get("address")
    school_type = data.get("school_type", "preschool")
    
    if not all([school_name, email]):
        return jsonify({"error": "School name and email are required"}), 400
    
    if school_type not in ['preschool', 'elementary', 'private']:
        return jsonify({"error": "Invalid school type"}), 400
    
    user_id = get_jwt_identity()
    
    # Check if school already exists for this user
    existing = SalesSchool.query.filter_by(
        school_name=school_name, 
        user_id=user_id
    ).first()
    
    if existing:
        return jsonify({"error": "School already exists"}), 400
    
    school = SalesSchool(
        school_name=school_name,
        contact_name=contact_name,
        email=email,
        phone=phone,
        address=address,
        school_type=school_type,
        user_id=user_id
    )
    
    # Set additional emails
    school.set_additional_emails(additional_emails)
    
    db.session.add(school)
    db.session.commit()
    
    return jsonify({"message": "School added successfully"})

@app.route("/api/my-schools", methods=["GET"])
@jwt_required()
def get_my_schools():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # If admin, return all schools; otherwise, return only user's schools
    if user.admin:
        schools = SalesSchool.query.all()
    else:
        schools = SalesSchool.query.filter_by(user_id=user_id).all()
    
    return jsonify([
        {
            "id": school.id,
            "school_name": school.school_name,
            "contact_name": school.contact_name,
            "email": school.email,
            "additional_emails": json.loads(school.additional_emails) if school.additional_emails else [],
            "all_emails": school.get_all_emails(),
            "phone": school.phone,
            "address": school.address,
            "school_type": school.school_type,
            "status": school.status,
            "notes": school.notes,
            "created_at": school.created_at,
            "user_name": school.user.name if hasattr(school, 'user') else None
        }
        for school in schools
    ])

@app.route("/api/schools", methods=["GET"])
def get_schools():
    """Return all schools from the database."""
    schools = School.query.all()
    return jsonify([
        {"id": s.id, "name": s.name, "address": s.address, "phone": s.phone, "contact": s.contact, "email": s.email}
        for s in schools
    ])

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
                school_key = school_name.lower().strip()
                
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
        
        # Second pass: Create database entries
        for school_key, school_data in schools_dict.items():
            try:
                school_name = school_data['school_name']
                emails = school_data['emails']
                
                # Check if school already exists for this user
                existing = SalesSchool.query.filter_by(
                    school_name=school_name,
                    user_id=user_id
                ).first()
                
                if existing:
                    schools_skipped += 1
                    print(f"DEBUG: School '{school_name}' already exists, skipping")
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

@app.route("/api/send-email", methods=["POST"])
@jwt_required()
def send_email():
    data = request.get_json()
    school_ids = data.get("school_ids", [])
    subject = data.get("subject", "Let's Connect! PSA Programs")
    send_to_all_emails = data.get("send_to_all_emails", False)  # New option
    
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
    if user.admin:
        schools = SalesSchool.query.filter(SalesSchool.id.in_(school_ids)).all()
    else:
        schools = SalesSchool.query.filter(
            SalesSchool.id.in_(school_ids),
            SalesSchool.user_id == user_id
        ).all()
    
    if not schools:
        return jsonify({"error": "No valid schools found"}), 400

    sent_count = 0
    errors = []
    total_emails_to_send = 0

    # Calculate total emails to send
    for school in schools:
        if send_to_all_emails:
            total_emails_to_send += len(school.get_all_emails())
        else:
            total_emails_to_send += 1
    
    # Limit total emails to prevent timeout
    if total_emails_to_send > 15:
        return jsonify({"error": f"Too many emails to send ({total_emails_to_send}). Maximum is 15 per batch."}), 400

    for school in schools:
        try:
            print(f"DEBUG: Processing school: {school.school_name}")
            
            # Determine email template and PDF files based on school type
            if school.school_type == 'preschool':
                email_template = PRESCHOOL_EMAIL_TEMPLATE
                pdf_files = ["PSA TOTS seasonal flyer.pdf", "PSA TOTS year round flyer.pdf", "PSA TOTS Recommendation (Primrose School).pdf"]
            elif school.school_type == 'private':
                email_template = PRIVATE_SCHOOL_EMAIL_TEMPLATE
                pdf_files = ["PSA After School.pdf", "PSA Recommendation (St. Theresa).pdf", "PSA Recommendation (St. Veronica).pdf"]  
            else:  # elementary
                email_template = ELEMENTARY_EMAIL_TEMPLATE
                pdf_files = ["PSA After School.pdf", "PSA Recommendation Letter (Madison Trust ES).pdf"]
            
            # Create email body
            body = render_template_string(
                email_template,
                user_name=user.name,
                user_email=user.email,
                school_name=school.school_name,
                contact_name=school.contact_name or "Director/Administrator"
            )
            
            # Get emails to send to
            if send_to_all_emails:
                emails_to_send = school.get_all_emails()
            else:
                emails_to_send = [school.email]  # Just primary email
            
            # Send to each email address
            school_sent_count = 0
            for email_address in emails_to_send:
                try:
                    success = send_email_with_attachments(
                        from_email=user.email,
                        from_password=user.email_password,
                        to_email=email_address,
                        subject=subject,
                        body=body,
                        pdf_files=pdf_files,
                        from_name=user.name
                    )
                    
                    if success:
                        print(f"DEBUG: Email sent successfully to {email_address}")
                        
                        # Log each email separately
                        new_email = SentEmail(
                            school_name=school.school_name,
                            school_email=email_address,
                            user_id=user_id,
                            responded=False,
                            followup_sent=False
                        )
                        db.session.add(new_email)
                        
                        school_sent_count += 1
                        sent_count += 1
                    else:
                        errors.append(f"Failed to send to {school.school_name} ({email_address})")
                        
                except Exception as e:
                    error_msg = f"Failed to send to {school.school_name} ({email_address}): {str(e)}"
                    print(f"DEBUG ERROR: {error_msg}")
                    errors.append(error_msg)
            
            # Update school status if at least one email was sent
            if school_sent_count > 0:
                school.status = 'contacted'
            
        except Exception as e:
            error_msg = f"Failed to process {school.school_name}: {str(e)}"
            print(f"DEBUG ERROR: {error_msg}")
            errors.append(error_msg)
    
    try:
        db.session.commit()
        print(f"DEBUG: Database committed successfully")
    except Exception as e:
        print(f"DEBUG: Database commit error: {str(e)}")
        db.session.rollback()
    
    return jsonify({
        "status": f"{sent_count} emails sent successfully" if sent_count > 0 else "Failed to send emails",
        "sent_count": sent_count,
        "total_emails_attempted": total_emails_to_send,
        "errors": errors
    })

def send_email_with_attachments(from_email, from_password, to_email, subject, body, pdf_files, from_name):
    """Send email with PDF attachments using SMTP"""
    try:
        # Create message
        msg = MIMEMultipart('mixed')  # Specify multipart type
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Set charset for the entire message
        msg.set_charset('utf-8')
        
        # Add body to email with proper encoding
        text_part = MIMEText(body, 'plain', 'utf-8')
        msg.attach(text_part)
        
        # Define the path where PDFs are stored
        pdf_directory = os.path.join(os.path.dirname(__file__), 'pdf_attachments')
        
        # Attach PDF files
        for pdf_file in pdf_files:
            pdf_path = os.path.join(pdf_directory, pdf_file)
            
            if os.path.exists(pdf_path):
                print(f"DEBUG: Attaching PDF: {pdf_file}")
                with open(pdf_path, "rb") as attachment:
                    part = MIMEBase('application', 'pdf')
                    part.set_payload(attachment.read())
                
                # Encode file in ASCII characters to send by email    
                encoders.encode_base64(part)
                
                # Add header as key/value pair to attachment part
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename="{pdf_file}"',  # Added quotes around filename
                )
                
                # Attach the part to message
                msg.attach(part)
            else:
                print(f"WARNING: PDF file not found: {pdf_path}")
                print(f"DEBUG: Looking for file at: {pdf_path}")
                # List files in the directory for debugging
                if os.path.exists(pdf_directory):
                    files_in_dir = os.listdir(pdf_directory)
                    print(f"DEBUG: Files in pdf_attachments directory: {files_in_dir}")
                else:
                    print(f"DEBUG: pdf_attachments directory does not exist at: {pdf_directory}")
        
        # Create SMTP session
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Enable security
        server.login(from_email, from_password)
        
        # Convert message to string and send
        # The key fix: use as_bytes() instead of as_string() to handle Unicode properly
        message_bytes = msg.as_bytes()
        server.send_message(msg, from_email, [to_email])  # Use send_message instead of sendmail
        server.quit()
        
        return True
        
    except Exception as e:
        print(f"Error sending email with attachments: {str(e)}")
        traceback.print_exc()
        return False

# Also update the followup email function
@app.route("/api/send-followup", methods=["POST"])
@jwt_required()
def send_followup():
    data = request.get_json()
    email_id = data.get("email_id")
    
    if not email_id:
        return jsonify({"error": "Missing email_id"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.email_password:
        return jsonify({"error": "User not connected with email"}), 400

    # Get the original email record
    original_email = SentEmail.query.filter_by(id=email_id, user_id=user_id).first()
    if not original_email:
        return jsonify({"error": "Email not found"}), 404

    if original_email.followup_sent:
        return jsonify({"error": "Follow-up already sent"}), 400

    # Get the school to determine type
    school = SalesSchool.query.filter_by(
        school_name=original_email.school_name,
        email=original_email.school_email,
        user_id=user_id
    ).first()
    
    # Choose followup template based on school type
    if school and school.school_type == 'preschool':
        followup_template = PRESCHOOL_FOLLOWUP_TEMPLATE
    elif school and school.school_type == 'private':
        followup_template = PRIVATE_SCHOOL_FOLLOWUP_TEMPLATE
    else:  # elementary
        followup_template = ELEMENTARY_FOLLOWUP_TEMPLATE

    # Create follow-up email body
    followup_body = render_template_string(
        followup_template,
        school_name=original_email.school_name,
        user_name=user.name,
        user_email=user.email
    )

    try:
        # Use the same send_email_with_attachments function that works for regular emails
        success = send_email_with_attachments(
            from_email=user.email,
            from_password=user.email_password,
            to_email=original_email.school_email,
            subject="Follow-Up: PSA Programs",
            body=followup_body,
            pdf_files=[],  # No attachments for follow-ups
            from_name=user.name
        )
        
        if success:
            original_email.followup_sent = True
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
    if user.admin:
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
        
        email_data.append({
            "id": email.id,
            "school_name": email.school_name,
            "school_email": email.school_email,
            "sent_at": email.sent_at.isoformat(),
            "sent_at_formatted": email.sent_at.strftime("%b %d, %Y"),
            "days_ago": days_ago,
            "responded": email.responded,
            "followup_sent": email.followup_sent,
            "has_reply_content": bool(email.reply_content),
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

@app.route("/api/find-schools", methods=["POST"])
def find_schools():
    data = request.get_json()
    address = data.get("address")
    keywords = data.get("keywords", ["elementary school", "day care", "preschool", "kindercare", "montessori"])
    if not address:
        return jsonify({"error": "No address provided"}), 400

    # If address is a zip code or a city, append "USA" to prioritize US geocoding
    if re.fullmatch(r"\d{5}", address.strip()):
        address = f"{address.strip()} USA"
    elif re.fullmatch(r"[a-zA-Z ]+", address.strip()):
        address = f"{address.strip()} USA"

    # Get normalized names of schools we already do business with
    happy_feet_names = set([normalize_name(s["name"]) for s in happy_feet])
    psa_names = set([normalize_name(s["name"]) for s in psa_preschools])
    excluded_names = happy_feet_names | psa_names

    # Geocode the address
    lat, lng = geocode_address(address)
    if lat is None or lng is None:
        return jsonify({"error": "Address not found"}), 404
    location = {"lat": lat, "lng": lng}

    # Find nearby schools using Places API
    places_url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json"
    base_params = {
        "location": f"{location['lat']},{location['lng']}",
        "radius": 5000,
        "key": GOOGLE_API_KEY
    }

    results = []
    for place_type in ["school"]:
        for kw in keywords:
            params = base_params.copy()
            params["type"] = place_type
            params["keyword"] = kw
            resp = requests.get(places_url, params=params).json()
            results.extend(resp.get("results", []))

    # Remove duplicates by place_id
    unique = {}
    for result in results:
        pid = result.get("place_id")
        if pid and pid not in unique:
            unique[pid] = result

    # Filter out schools that are already in Happy Feet or PSA tables (fuzzy match)
    schools = []
    for result in unique.values():
        school_name = result.get("name", "")
        norm_name = normalize_name(school_name)
        if any(norm_name == ex or norm_name in ex or ex in norm_name for ex in excluded_names):
            continue
        schools.append({
            "name": result.get("name"),
            "address": result.get("vicinity"),
            "lat": result["geometry"]["location"]["lat"],
            "lng": result["geometry"]["location"]["lng"],
            "place_id": result.get("place_id")
        })

    return jsonify({
        "schools": schools,
        "location": location,
        "google_api_key": GOOGLE_API_KEY
    })

# ====================================================
# API ENDPOINTS - ROUTE PLANNING
# ====================================================

@app.route("/api/route-plan", methods=["POST"])
def route_plan():
    """Calculate shortest route visiting all selected schools."""
    data = request.get_json()
    schools = data.get("schools", [])
    start_address = data.get("start_address")
    if len(schools) < 2:
        return jsonify({"error": "Select at least two schools"}), 400
    if not start_address:
        return jsonify({"error": "No starting address provided"}), 400

    # Geocode the starting address
    start_lat, start_lng = geocode_address(start_address)
    if start_lat is None or start_lng is None:
        return jsonify({"error": "Starting address not found"}), 404

    # Build distance matrix (from start to each school, and between schools)
    n = len(schools)
    dist = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            if i != j:
                dist[i][j] = haversine(
                    schools[i]["lat"], schools[i]["lng"],
                    schools[j]["lat"], schools[j]["lng"]
                )

    # Calculate distance from start to each school
    start_to_school = [
        haversine(start_lat, start_lng, s["lat"], s["lng"]) for s in schools
    ]

    # Brute-force TSP starting from start location
    indices = list(range(n))
    min_order = None
    min_dist = float('inf')
    for perm in permutations(indices):
        d = start_to_school[perm[0]]  # from start to first school
        d += sum(dist[perm[i]][perm[i+1]] for i in range(n-1))
        if d < min_dist:
            min_dist = d
            min_order = perm

    route = [schools[i]["place_id"] for i in min_order]
    return jsonify({"route": route})

# ====================================================
# API ENDPOINTS - MAP VISUALIZATION
# ====================================================

@app.route("/api/map-schools", methods=["GET"])
def map_schools():
    return jsonify(MAP_SCHOOL_CACHE)

@app.route("/api/refresh-map-schools", methods=["POST"])
def refresh_map_schools():
    global MAP_SCHOOL_CACHE
    new_sheet_rows = load_PSA_school_sheet()
    psa_preschools, happy_feet = split_sheet_schools(new_sheet_rows)

    happy_feet_geocoded = []
    for s in happy_feet:
        lat, lng = geocode_address(s["address"])
        happy_feet_geocoded.append({
            "name": s["name"],
            "address": s["address"],
            "type": "happyfeet",
            "lat": lat,
            "lng": lng
        })
        time.sleep(0.1)  # 100ms delay

    psa_preschools_geocoded = []
    for s in psa_preschools:
        lat, lng = geocode_address(s["address"])
        psa_preschools_geocoded.append({
            "name": s["name"],
            "address": s["address"],
            "type": "psa",
            "lat": lat,
            "lng": lng
        })
        time.sleep(0.1)  # 100ms delay

    rec_geocoded = []
    for site in REC_SITES:
        lat, lng = geocode_address(site["address"])
        rec_geocoded.append({
            "name": site["name"],
            "address": site["address"],
            "type": "rec",
            "lat": lat,
            "lng": lng
        })

    MAP_SCHOOL_CACHE = {
        "happyfeet": happy_feet_geocoded,
        "psa": psa_preschools_geocoded,
        "rec": rec_geocoded,
    }
    return jsonify({"status": "refreshed"})

# ====================================================
# API ENDPOINTS - TEAM STATS
# ====================================================

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

    # Verify user owns this email or is admin
    if user.admin:
        email_record = SentEmail.query.get(email_id)
    else:
        email_record = SentEmail.query.filter_by(id=email_id, user_id=user_id).first()
    
    if not email_record:
        return jsonify({"error": "Email record not found"}), 404

    try:
        # Send the custom reply
        success = send_email_with_attachments(
            from_email=user.email,
            from_password=user.email_password,
            to_email=to_email,
            subject=subject,
            body=message,
            pdf_files=[],  # No attachments for replies
            from_name=user.name
        )
        
        if success:
            return jsonify({"status": "Custom reply sent successfully"})
        else:
            return jsonify({"error": "Failed to send custom reply"}), 500
            
    except Exception as e:
        print(f"Error sending custom reply: {str(e)}")
        return jsonify({"error": f"Failed to send custom reply: {str(e)}"}), 500

# ====================================================
# APPLICATION STARTUP
# ====================================================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

