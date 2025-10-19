# ===== IMPORTS ======

import os
import requests
import re
import json
from itertools import permutations
from math import radians, cos, sin, sqrt, atan2
import time
import imaplib
import email
from email.header import decode_header
import ssl
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, render_template_string
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv

import gspread
from oauth2client.service_account import ServiceAccountCredentials
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)

from apscheduler.schedulers.background import BackgroundScheduler
import atexit




# ====== ENVIRONMENT & APP SETUP ======
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=[
    "https://psasales-6l22ucils-david-darrs-projects.vercel.app",
    "https://www.salespsa.com",
    "https://salespsa.com"
])

# ====== DATABASE CONFIGURATION ======
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'postgresql://postgres.dlnfvtudzyyabixedniz:Pandaplayz6!@aws-0-us-east-1.pooler.supabase.com:6543/postgres'
)
db = SQLAlchemy(app)

# ====== JWT AUTHENTICATION SETUP ======
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
jwt = JWTManager(app)

# ====== GOOGLE SHEETS LOADING ======
# Sheet of Happy Feet and PSA Schools
def load_PSA_school_sheet():
    """Load the new Google Sheet for PSA Preschools and Happy Feet."""
    scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
    service_account_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    service_account_info = json.loads(service_account_json)
    service_account_info["private_key"] = service_account_info["private_key"].replace("\\n", "\n")
    creds = ServiceAccountCredentials.from_json_keyfile_dict(service_account_info, scope)
    client = gspread.authorize(creds)
    sheet = client.open('PSA Preschools')  # <-- change to your new sheet name
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

# Cached sheet data (refreshed via endpoint)
psa_preschools, happy_feet = split_sheet_schools(load_PSA_school_sheet())

REC_SITES = [
    {"name": "Hanson Park", "address": "22831 Hanson Park Dr, Aldie, VA 20105"},
    {"name": "Heron Overlook", "address": "20550 Heron overlook Plz, Ashburn, VA 20147"}
]

GENERIC_NAMES = {"elementary", "preschool", "school name", "elementary school"}


# ====== DATABASE MODELS ======
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
    status = db.Column(db.String, default='pending')  # pending, contacted, responded, etc.
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    user = db.relationship('User', backref=db.backref('sales_schools', lazy=True))

# ====== USER MODELS ======
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

# ====== MAIL CONFIGURATION ======
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # or your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  # your server email
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # your server email password or app password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")
mail = Mail(app)

# ====== UTILITY FUNCTIONS ======
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

def check_email_replies():
    """Check for email replies and update the database"""
    print("Starting email reply check...")
    
    # Get all users who have sent emails and have email passwords configured
    users_with_emails = User.query.filter(
        User.email_password.isnot(None),
        User.id.in_(db.session.query(SentEmail.user_id).distinct())
    ).all()
    
    for user in users_with_emails:
        try:
            print(f"Checking emails for user: {user.email}")
            check_user_email_replies(user)
        except Exception as e:
            print(f"Error checking emails for {user.email}: {str(e)}")
    
    print("Email reply check completed")

def check_user_email_replies(user):
    """Check email replies for a specific user"""
    try:
        print(f"DEBUG: Starting email check for {user.email}")
        
        # Connect to Gmail IMAP
        context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993, ssl_context=context)
        mail.login(user.email, user.email_password)
        
        # Select inbox
        mail.select("inbox")
        
        # Get emails from the last 7 days
        since_date = (datetime.utcnow() - timedelta(days=7)).strftime("%d-%b-%Y")
        print(f"DEBUG: Searching for emails since {since_date}")
        
        # Search for emails
        status, messages = mail.search(None, f'SINCE {since_date}')
        
        if status == "OK":
            email_ids = messages[0].split()
            print(f"DEBUG: Found {len(email_ids)} emails in inbox")
            
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
            
            replies_found = 0
            
            # Check recent emails
            for email_id in email_ids[-50:]:  # Check last 50 emails
                try:
                    status, msg_data = mail.fetch(email_id, "(RFC822)")
                    if status == "OK":
                        email_body = msg_data[0][1]
                        email_message = email.message_from_bytes(email_body)
                        
                        # Get sender email
                        sender = email_message.get("From", "")
                        sender_email = extract_email_from_string(sender).lower()
                        subject = email_message.get("Subject", "")
                        
                        print(f"DEBUG: Checking email from {sender_email} with subject: {subject}")
                        
                        # Check if this email is from a school we sent to
                        if sender_email in school_emails:
                            sent_email = school_emails[sender_email]
                            
                            # More strict reply detection
                            is_reply = False

                            # Check 1: Subject line indicates it's a reply
                            if (subject.lower().startswith("re:") or 
                                subject.lower().startswith("fwd:") or
                                "re:" in subject.lower()):
                                is_reply = True
                                print(f"DEBUG: Reply detected via subject line: {subject}")

                            # Check 2: Look for email threading (In-Reply-To header)
                            elif email_message.get("In-Reply-To") or email_message.get("References"):
                                is_reply = True
                                print(f"DEBUG: Reply detected via email threading headers")

                            # Check 3: Content analysis - look for quoted text or greeting patterns
                            else:
                                try:
                                    email_content = email_message.get_payload(decode=True).decode('utf-8', errors='ignore').lower()
                                    reply_indicators = [
                                        "thank you for your email",
                                        "thanks for reaching out", 
                                        "thank you for contacting",
                                        "interested in your",
                                        "would like to learn more",
                                        "please send me more information",
                                        "we are interested",
                                        "> on",  # Quoted text indicator
                                        "wrote:",  # Another quoted text indicator
                                        "sent from my"  # Mobile signature
                                    ]
                                    
                                    if any(phrase in email_content for phrase in reply_indicators):
                                        is_reply = True
                                        print(f"DEBUG: Reply detected via content analysis")
                                    else:
                                        print(f"DEBUG: Email content doesn't indicate a reply")
                                        
                                except Exception as e:
                                    print(f"DEBUG: Could not analyze email content: {str(e)}")

                            print(f"DEBUG: Final reply decision - Subject: '{subject}', Is_Reply: {is_reply}")
                            # ====== END UPDATED VALIDATION ======
                            
                            # Check the date - must be after we sent our email
                            email_date = email_message.get("Date", "")
                            try:
                                from email.utils import parsedate_to_datetime
                                received_date = parsedate_to_datetime(email_date)
                                if received_date <= sent_email.sent_at:
                                    print(f"DEBUG: Email date {received_date} is before sent date {sent_email.sent_at}, skipping")
                                    continue
                            except:
                                print(f"DEBUG: Could not parse email date: {email_date}")
                                continue
                            
                            if is_reply:
                                print(f"DEBUG: CONFIRMED REPLY from {sender_email} to {user.email}")
                                print(f"DEBUG: Subject: {subject}")
                                
                                # Mark as responded
                                sent_email.responded = True
                                replies_found += 1
                                
                                print(f"DEBUG: Marked email to {sent_email.school_name} as responded")
                            else:
                                print(f"DEBUG: Email from {sender_email} doesn't appear to be a reply (subject: {subject})")
                
                except Exception as e:
                    print(f"DEBUG: Error processing email {email_id}: {str(e)}")
                    continue
            
            if replies_found > 0:
                db.session.commit()
                print(f"DEBUG: Found and marked {replies_found} replies")
            else:
                print(f"DEBUG: No new replies found")
        
        mail.close()
        mail.logout()
        
    except Exception as e:
        print(f"DEBUG: Error connecting to email for {user.email}: {str(e)}")
        import traceback
        traceback.print_exc()

def extract_email_from_string(email_string):
    """Extract email address from 'Name <email@domain.com>' format"""
    import re
    
    # Handle multiple formats
    # 1. Name <email@domain.com>
    # 2. email@domain.com
    # 3. "Name" <email@domain.com>
    
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

# Initialize scheduler
scheduler = BackgroundScheduler()

def start_scheduler():
    """Start the background scheduler for checking email replies"""
    if not scheduler.running:
        # Check for email replies every 30 minutes
        scheduler.add_job(
            func=check_email_replies,
            trigger="interval",
            minutes=30,  # Check every 30 minutes
            id='email_reply_checker'
        )
        scheduler.start()
        print("Email reply checker scheduled to run every 30 minutes")
        
        # Shut down the scheduler when exiting the app
        atexit.register(lambda: scheduler.shutdown())

# Start the scheduler when the app starts
start_scheduler()

# ====== API ENDPOINTS ======

# --- USER API ---
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

@app.route("/api/add-school", methods=["POST"])
@jwt_required()
def add_school():
    data = request.get_json()
    school_name = data.get("school_name")
    email = data.get("email")
    contact_name = data.get("contact_name")
    phone = data.get("phone")
    address = data.get("address")
    
    if not all([school_name, email]):
        return jsonify({"error": "School name and email required"}), 400
    
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
            "status": school.status,
            "notes": school.notes,
            "created_at": school.created_at,
            "user_name": school.user.name if hasattr(school, 'user') else None  # Show which user added it
        }
        for school in schools
    ])

# --- School List API ---
@app.route("/api/schools", methods=["GET"])
def get_schools():
    """Return all schools from the database."""
    schools = School.query.all()
    return jsonify([
        {"id": s.id, "name": s.name, "address": s.address, "phone": s.phone, "contact": s.contact, "email": s.email}
        for s in schools
    ])

# --- School Finder API ---
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

# --- Route Planning API ---
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


# --- Email API ---
EMAIL_TEMPLATE = """
Hi {{ contact_name }},

My name is {{ user_name }}, and I'm with The Players Sports Academy (PSA) — a nonprofit organization offering fun, convenient sports activities for preschool students ages 2-5 right on campus during the school day. 

It was a pleasure learning about {{ school_name }}! I'd love to share information about our on-site sports programs.

PSA TOTS currently works with over 60 preschools in the Northern Virginia area, providing quality sports programs designed specifically for young learners.

Here's why schools and families love working with PSA:
• On-site convenience - Programs run during school hours with no extra work for your team
• All equipment provided - I bring everything needed for each session
• Flexible scheduling - Programs available seasonally or year-round
• Variety of activities - Soccer, Basketball, T-Ball, and Yoga designed for young learners
• Fundraising opportunity - Schools can raise funds through the programs

We would love to set up a free demo session so your students can experience the fun firsthand!

Would you be open to a quick call or meeting to discuss the details? Please let me know a date and time that works best for you.

Thank you for your time, and I look forward to the opportunity to work together!

Best regards,
{{ user_name }}
Sales Associate and Coach
{{ user_email }}
https://thepsasports.com
"""

FOLLOWUP_TEMPLATE = """
Hi there,

I wanted to follow up on my previous email regarding PSA's on-site sports programs for {{ school_name }}. We would love to set up a free demo session for your students to experience the fun firsthand.

Please let me know if you have any questions or would like to schedule a quick call to discuss further.

Best regards,  
{{ user_name }}  
Sales Associate and Coach  
{{ user_email }}
https://thepsasports.com
"""

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
    
    print(f"DEBUG: User email: {user.email}")
    print(f"DEBUG: User has email_password: {bool(user.email_password)}")
    print(f"DEBUG: Email password length: {len(user.email_password) if user.email_password else 0}")
    
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
    
    print(f"DEBUG: Found {len(schools)} schools to email")
    for school in schools:
        print(f"DEBUG: School - {school.school_name}, Email: {school.email}")
    
    if not schools:
        return jsonify({"error": "No valid schools found"}), 400

    sent_count = 0
    errors = []

    for school in schools:
        try:
            print(f"DEBUG: Processing school: {school.school_name}")
            
            # Create email body
            body = render_template_string(
                EMAIL_TEMPLATE,
                user_name=user.name,
                user_email=user.email,
                school_name=school.school_name,
                contact_name=school.contact_name or "Director/Administrator"
            )
            print(f"DEBUG: Email body created for {school.school_name}")

            # Configure Flask-Mail for this user
            print(f"DEBUG: Configuring mail with:")
            print(f"  - MAIL_USERNAME: {user.email}")
            print(f"  - MAIL_PASSWORD: {'*' * len(user.email_password)}")
            print(f"  - MAIL_SERVER: smtp.gmail.com")
            print(f"  - MAIL_PORT: 587")
            
            # Reconfigure mail settings for this user
            app.config['MAIL_USERNAME'] = user.email
            app.config['MAIL_PASSWORD'] = user.email_password
            app.config['MAIL_DEFAULT_SENDER'] = user.email
            app.config['MAIL_SERVER'] = 'smtp.gmail.com'
            app.config['MAIL_PORT'] = 587
            app.config['MAIL_USE_TLS'] = True
            app.config['MAIL_USE_SSL'] = False
            
            # Reinitialize mail with new config
            mail.init_app(app)
            
            print(f"DEBUG: Creating message...")
            msg = Message(
                subject=subject,
                recipients=[school.email],
                body=body,
                sender=user.email
            )
            print(f"DEBUG: Message created, attempting to send to {school.email}...")
            
            # Try to send the email
            mail.send(msg)
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
            
        except Exception as e:
            error_msg = f"Failed to send to {school.school_name}: {type(e).__name__}: {str(e)}"
            print(f"DEBUG ERROR: {error_msg}")
            errors.append(error_msg)
            
            # Print full traceback for debugging
            import traceback
            print(f"DEBUG TRACEBACK:")
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
    print(f"DEBUG: Final result: {result}")
    
    return jsonify(result)
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

    # Send follow-up email
    followup_body = render_template_string(
        FOLLOWUP_TEMPLATE,
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


# --- MAP API ---
MAP_SCHOOL_CACHE = {}

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
            "user_name": email.user.name if hasattr(email, 'user') else None  # Show which user sent it
        }
        for email in emails
    ])

# --- Delete Sent Email ---
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

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

