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
from datetime import datetime, timedelta
import traceback
import gspread

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
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
CORS(app, supports_credentials=True, origins=[
    "https://psasales-6l22ucils-david-darrs-projects.vercel.app",
    "https://www.salespsa.com",
    "https://salespsa.com"
])

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
    email = db.Column(db.String, nullable=False)
    phone = db.Column(db.String, nullable=True)
    address = db.Column(db.String, nullable=True)
    school_type = db.Column(db.String, nullable=False, default='preschool')  # NEW FIELD
    status = db.Column(db.String, default='pending')
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    user = db.relationship('User', backref=db.backref('sales_schools', lazy=True))

class SentEmail(db.Model):
    __tablename__ = 'sent_emails'
    id = db.Column(db.Integer, primary_key=True)
    school_name = db.Column(db.String, nullable=False)
    school_email = db.Column(db.String, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded = db.Column(db.Boolean, default=False)
    followup_sent = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('sent_emails', lazy=True))

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
    """Check for email replies and update the database"""
    with app.app_context():
        start_time = datetime.utcnow()
        print(f"=== AUTOMATIC EMAIL REPLY CHECK STARTED at {start_time} ===")
        
        try:
            # Get all users who have sent emails and have email passwords configured
            users_with_emails = User.query.filter(
                User.email_password.isnot(None),
                User.id.in_(db.session.query(SentEmail.user_id).distinct())
            ).all()
            
            print(f"Found {len(users_with_emails)} users with email configurations")
            
            total_replies_found = 0
            
            for user in users_with_emails:
                try:
                    print(f"Checking emails for user: {user.email}")
                    replies_before = SentEmail.query.filter_by(user_id=user.id, responded=True).count()
                    check_user_email_replies(user)
                    replies_after = SentEmail.query.filter_by(user_id=user.id, responded=True).count()
                    new_replies = replies_after - replies_before
                    total_replies_found += new_replies
                    print(f"Found {new_replies} new replies for {user.email}")
                except Exception as e:
                    print(f"Error checking emails for {user.email}: {str(e)}")
                    import traceback
                    traceback.print_exc()
            
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            print(f"=== AUTOMATIC EMAIL REPLY CHECK COMPLETED at {end_time} ===")
            print(f"Duration: {duration:.2f} seconds")
            print(f"Total new replies found: {total_replies_found}")
            print(f"Next check scheduled for: {(start_time + timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')} UTC")
            
        except Exception as e:
            print(f"ERROR in automatic email check: {str(e)}")
            import traceback
            traceback.print_exc()

def check_user_email_replies(user):
    """Check email replies for a specific user - focused on 'Re:' subjects only"""
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
                    status, msg_data = mail.fetch(email_id, "(RFC822)")
                    if status == "OK":
                        email_body = msg_data[0][1]
                        email_message = email.message_from_bytes(email_body)
                        
                        # Get sender email and subject
                        sender = email_message.get("From", "")
                        sender_email = extract_email_from_string(sender).lower()
                        subject = email_message.get("Subject", "")
                        email_date = email_message.get("Date", "")
                        
                        print(f"DEBUG: Checking Re: email from {sender_email}")
                        print(f"DEBUG: Subject: '{subject}'")
                        print(f"DEBUG: Date: {email_date}")
                        
                        # Check if this email is from a school we sent to
                        if sender_email in school_emails:
                            sent_email = school_emails[sender_email]
                            
                            print(f"DEBUG: Found email from watched school: {sender_email}")
                            
                            # Validate the email date is after we sent our original email
                            try:
                                from email.utils import parsedate_to_datetime
                                received_date = parsedate_to_datetime(email_date)
                                
                                # Compare dates (both should be timezone-aware or both naive)
                                sent_at = sent_email.sent_at
                                if sent_at.tzinfo is None and received_date.tzinfo is not None:
                                    # Make sent_at timezone-aware to match received_date
                                    sent_at = pytz.UTC.localize(sent_at)
                                elif sent_at.tzinfo is not None and received_date.tzinfo is None:
                                    # Make received_date timezone-aware to match sent_at
                                    received_date = pytz.UTC.localize(received_date)
                                
                                if received_date <= sent_at:
                                    print(f"DEBUG: Reply date {received_date} is before/equal to sent date {sent_at}, skipping")
                                    continue
                                    
                                print(f"DEBUG: Date validation passed: received {received_date} > sent {sent_at}")
                                
                            except Exception as date_error:
                                print(f"DEBUG: Date parsing failed: {date_error}")
                                # If we can't parse dates, still proceed if it's a "Re:" email
                                print(f"DEBUG: Proceeding anyway since subject contains 'Re:'")
                            
                            # Since we already filtered for "Re:" in the search, this is a reply
                            print(f"DEBUG: ✅ CONFIRMED REPLY from {sender_email}")
                            print(f"DEBUG: Reply subject: '{subject}'")
                            
                            # Mark as responded
                            sent_email.responded = True
                            replies_found += 1
                            
                            print(f"DEBUG: Marked email to {sent_email.school_name} as responded")
                            
                        else:
                            print(f"DEBUG: Re: email from {sender_email} is not from a school we're watching")
                
                except Exception as e:
                    print(f"DEBUG: Error processing email {email_id}: {str(e)}")
                    continue
            
            if replies_found > 0:
                db.session.commit()
                print(f"DEBUG: ✅ Successfully marked {replies_found} replies")
            else:
                print(f"DEBUG: ❌ No replies found from watched schools")
        else:
            print(f"DEBUG: Email search failed with status: {status}")
        
        mail.close()
        mail.logout()
        
    except Exception as e:
        print(f"DEBUG: Error connecting to email for {user.email}: {str(e)}")
        import traceback
        traceback.print_exc()

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
• On-site convenience - Programs run during school hours with no extra work for your team
• Age-appropriate activities - All programs designed specifically for 2-5 year olds
• All equipment provided - I bring everything needed for each session
• Flexible scheduling - Programs available seasonally or year-round
• Variety of activities - Soccer, Basketball, T-Ball, and Yoga designed for preschoolers
• Fundraising opportunity - Schools can raise funds through the programs
• Professional coaching - All coaches are trained in early childhood development

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
• No cost to the school - Parents enroll directly, and we offer a revenue-share model to support your PTA or school initiatives.
• Hassle-free - We handle everything: professional coaches, equipment, registration, and student pick-up after each session.
• Flexible offerings - Programs run seasonally (6-8 weeks) with options like soccer, basketball, flag football, and more.
• Community-focused - We provide scholarships and fundraising support to help all students participate.

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
https://thepsasports.com
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
https://thepsasports.com
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
    """Manually trigger email reply checking"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if not user.email_password:
        return jsonify({"error": "Email settings not configured"}), 400
    
    try:
        if user.admin:
            # Admin can check all emails
            check_email_replies()
            return jsonify({"status": "Checked all user emails for replies"})
        else:
            # Regular user can only check their own
            check_user_email_replies(user)
            return jsonify({"status": "Checked your emails for replies"})
    except Exception as e:
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
    contact_name = data.get("contact_name")
    phone = data.get("phone")
    address = data.get("address")
    school_type = data.get("school_type", "preschool")  # NEW FIELD
    
    if not all([school_name, email]):
        return jsonify({"error": "School name and email required"}), 400
    
    # Validate school type
    if school_type not in ['preschool', 'elementary']:
        return jsonify({"error": "School type must be 'preschool' or 'elementary'"}), 400
    
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
        school_type=school_type,  # NEW FIELD
        user_id=user_id
    )
    
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
            "phone": school.phone,
            "address": school.address,
            "school_type": school.school_type,  # NEW FIELD
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

# ====================================================
# API ENDPOINTS - EMAIL OPERATIONS
# ====================================================

@app.route("/api/send-email", methods=["POST"])
@jwt_required()
def send_email():
    data = request.get_json()
    school_ids = data.get("school_ids", [])
    subject = data.get("subject", "Let's Connect! PSA Programs")
    
    print(f"DEBUG: Received school_ids: {school_ids}")
    
    if not school_ids:
        return jsonify({"error": "No schools selected"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    print(f"DEBUG: User found: {user.name if user else 'None'}")
    
    if not user:
        return jsonify({"error": "User not found"}), 400
    
    if not user.email_password:
        return jsonify({"error": "Email settings not configured"}), 400

    # Get selected schools - admins can email any school, regular users only their own
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

    for school in schools:
        try:
            print(f"DEBUG: Processing school: {school.school_name} (Type: {school.school_type})")
            
            # Choose template, subject, and PDFs based on school type
            if school.school_type == 'preschool':
                email_template = PRESCHOOL_EMAIL_TEMPLATE
                email_subject = f"Fun Sports Programs for {school.school_name} Preschoolers!"
                pdf_files = [
                    "PSA TOTS year round flyer.pdf",
                    "PSA TOTS seasonal flyer.pdf",
                    "PSA TOTS Recommendation (Primrose School).pdf"
                ]
            else:  # elementary
                email_template = ELEMENTARY_EMAIL_TEMPLATE
                email_subject = f"Sports Programs for {school.school_name} Students"
                pdf_files = [
                    "PSA After School.pdf",
                    "PSA Recommendation Letter (Madison Trust ES).pdf"
                ]
            
            # Create email body
            body = render_template_string(
                email_template,
                user_name=user.name,
                user_email=user.email,
                school_name=school.school_name,
                contact_name=school.contact_name or "Director/Administrator"
            )
            
            # Send email with attachments using SMTP directly
            success = send_email_with_attachments(
                from_email=user.email,
                from_password=user.email_password,
                to_email=school.email,
                subject=email_subject,
                body=body,
                pdf_files=pdf_files,
                from_name=user.name
            )
            
            if success:
                print(f"DEBUG: Email sent successfully to {school.email}")
                
                # Log the email
                new_email = SentEmail(
                    school_name=school.school_name,
                    school_email=school.email,
                    user_id=user_id,
                    responded=False,
                    followup_sent=False
                )
                db.session.add(new_email)
                
                # Update school status
                school.status = 'contacted'
                sent_count += 1
            else:
                errors.append(f"Failed to send to {school.school_name}")
            
        except Exception as e:
            error_msg = f"Failed to send to {school.school_name}: {str(e)}"
            print(f"DEBUG ERROR: {error_msg}")
            errors.append(error_msg)
            traceback.print_exc()
    
    try:
        db.session.commit()
        print(f"DEBUG: Database committed successfully")
    except Exception as e:
        print(f"DEBUG: Database commit error: {str(e)}")
    
    result = {
        "status": f"{sent_count} emails sent" if sent_count > 0 else "Failed to send emails",
        "sent_count": sent_count,
        "errors": errors
    }
    
    return jsonify(result)

def send_email_with_attachments(from_email, from_password, to_email, subject, body, pdf_files, from_name):
    """Send email with PDF attachments using SMTP"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Add body to email with proper encoding
        msg.attach(MIMEText(body, 'plain', 'utf-8'))  # Specify UTF-8 encoding
        
        # Define the path where PDFs are stored
        pdf_directory = os.path.join(os.path.dirname(__file__), 'pdf_attachments')
        
        # Attach PDF files
        for pdf_file in pdf_files:
            pdf_path = os.path.join(pdf_directory, pdf_file)
            
            if os.path.exists(pdf_path):
                print(f"DEBUG: Attaching PDF: {pdf_file}")
                with open(pdf_path, "rb") as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                
                # Encode file in ASCII characters to send by email    
                encoders.encode_base64(part)
                
                # Add header as key/value pair to attachment part
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {pdf_file}',
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
        
        # Send email with proper encoding
        text = msg.as_string()
        # Encode the message as UTF-8 bytes before sending
        server.sendmail(from_email, to_email, text)
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
    else:
        followup_template = ELEMENTARY_FOLLOWUP_TEMPLATE

    # Send follow-up email
    followup_body = render_template_string(
        followup_template,
        school_name=original_email.school_name,
        user_name=user.name,
        user_email=user.email
    )

    try:
        # Configure Flask-Mail for this user
        app.config['MAIL_USERNAME'] = user.email
        app.config['MAIL_PASSWORD'] = user.email_password
        app.config['MAIL_DEFAULT_SENDER'] = user.email
        
        msg = Message(
            subject="Follow-Up: PSA Programs",
            recipients=[original_email.school_email],
            body=followup_body,
            sender=user.email
        )
        mail.send(msg)
        
        original_email.followup_sent = True
        db.session.commit()
        return jsonify({"status": "follow-up sent"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    
    return jsonify([
        {
            "id": email.id,
            "school_name": email.school_name,
            "school_email": email.school_email,
            "sent_at": email.sent_at,
            "responded": email.responded,
            "followup_sent": email.followup_sent,
            "user_name": email.user.name if hasattr(email, 'user') else None
        }
        for email in emails
    ])

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
# APPLICATION STARTUP
# ====================================================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

