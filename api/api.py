# ===== IMPORTS ======

import os
import requests
import re
import json
from itertools import permutations
from math import radians, cos, sin, sqrt, atan2

from flask import Flask, request, jsonify, render_template_string
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv

import gspread
from oauth2client.service_account import ServiceAccountCredentials
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import base64
from email.mime.text import MIMEText

from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)






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
def load_all_sheets():
    """Load all worksheets from Google Sheets into a dictionary."""
    scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
    service_account_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    service_account_info = json.loads(service_account_json)
    service_account_info["private_key"] = service_account_info["private_key"].replace("\\n", "\n")
    creds = ServiceAccountCredentials.from_json_keyfile_dict(service_account_info, scope)
    client = gspread.authorize(creds)
    sheet = client.open('PSA sales from Scratch')
    all_data = {}
    for worksheet in sheet.worksheets():
        rows = worksheet.get_all_values()
        all_data[worksheet.title] = rows
    return all_data

# Cached sheet data (refreshed via endpoint)
ALL_SHEET_DATA = load_all_sheets()

GENERIC_NAMES = {"elementary", "preschool", "school name", "elementary school"}

def get_all_sheet_school_names():
    """Return a set of normalized school names from all sheets, excluding generic names."""
    excluded_names = set()
    for sheet_rows in ALL_SHEET_DATA.values():
        for row in sheet_rows:
            if row and row[0]:
                norm = normalize_name(row[0])
                if norm not in GENERIC_NAMES:
                    excluded_names.add(norm)
    return excluded_names

# ====== DATABASE MODELS ======
class School(db.Model):
    __tablename__ = 'schools'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    address = db.Column(db.String, nullable=False)
    phone = db.Column(db.String, nullable=False)
    contact = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)

class HappyFeetSchool(db.Model):
    __tablename__ = 'Happy Feet Schools'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)

class PSASchool(db.Model):
    __tablename__ = 'PSA Schools'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)

# ====== USER MODELS ======
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    phone = db.Column(db.String, nullable=True)
    password_hash = db.Column(db.String, nullable=False)
    gmail_access_token = db.Column(db.String, nullable=True)      # <-- Add this
    gmail_refresh_token = db.Column(db.String, nullable=True)     # <-- And this

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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

def send_gmail(user, to_email, subject, body):
    creds = Credentials(
        token=user.gmail_access_token,
        refresh_token=user.gmail_refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        scopes=["https://www.googleapis.com/auth/gmail.send"]
    )
    service = build('gmail', 'v1', credentials=creds)
    message = MIMEText(body)
    message['to'] = to_email
    message['from'] = user.email
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    send_message = {'raw': raw}
    sent = service.users().messages().send(userId="me", body=send_message).execute()
    return sent

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
            "user": {"id": user.id, "name": user.name, "email": user.email, "phone": user.phone}
        })
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": user.id, "name": user.name, "email": user.email, "phone": user.phone})

@app.route("/api/google-login", methods=["POST"])
def google_login():
    data = request.get_json()
    code = data.get("code")  # <-- use 'code' instead of 'token'
    if not code:
        return jsonify({"error": "Missing Google auth code"}), 400

    # Exchange code for tokens
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = "postmessage"  # for SPA

    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }
    token_resp = requests.post(token_url, data=token_data)
    if not token_resp.ok:
        return jsonify({"error": "Failed to exchange code"}), 400
    tokens = token_resp.json()
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    from google.auth.transport.requests import Request as GoogleRequest
    from google.oauth2 import id_token
    idinfo = id_token.verify_oauth2_token(tokens["id_token"], GoogleRequest(), client_id)
    email = idinfo["email"]
    name = idinfo.get("name", email.split("@")[0])
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(name=name, email=email, phone=None, password_hash="")
        db.session.add(user)
    user.gmail_access_token = access_token
    user.gmail_refresh_token = refresh_token
    db.session.commit()
    access_token_jwt = create_access_token(identity=str(user.id))
    return jsonify({
        "access_token": access_token_jwt,
        "user": {"id": user.id, "name": user.name, "email": user.email, "phone": user.phone}
    })

# --- Sheets API ---
@app.route("/api/team-sheets", methods=["GET"])
def get_team_sheets():
    """Return all sheet data for frontend display."""
    return jsonify(ALL_SHEET_DATA)

@app.route("/api/refresh-sheets", methods=["POST"])
def refresh_sheets():
    """Reload all sheets from Google Sheets."""
    global ALL_SHEET_DATA
    ALL_SHEET_DATA = load_all_sheets()
    return jsonify({"status": "refreshed"})

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
    """Find nearby schools not already in the database or sheets."""
    data = request.get_json()
    address = data.get("address")
    keywords = data.get("keywords", ["elementary school", "day care", "preschool", "kindercare", "montessori"])
    if not address:
        return jsonify({"error": "No address provided"}), 400

    # Get normalized names of schools we already do business with
    happy_feet_names = set([normalize_name(s.name) for s in HappyFeetSchool.query.all()])
    psa_names = set([normalize_name(s.name) for s in PSASchool.query.all()])
    excluded_names = happy_feet_names | psa_names | get_all_sheet_school_names()

    # Geocode the address
    geo_url = f"https://maps.googleapis.com/maps/api/geocode/json"
    geo_params = {"address": address, "key": GOOGLE_API_KEY}
    geo_resp = requests.get(geo_url, params=geo_params).json()
    if not geo_resp["results"]:
        return jsonify({"error": "Address not found"}), 404
    location = geo_resp["results"][0]["geometry"]["location"]

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
    geo_url = f"https://maps.googleapis.com/maps/api/geocode/json"
    geo_params = {"address": start_address, "key": GOOGLE_API_KEY}
    geo_resp = requests.get(geo_url, params=geo_params).json()
    if not geo_resp["results"]:
        return jsonify({"error": "Starting address not found"}), 404
    start_location = geo_resp["results"][0]["geometry"]["location"]
    start_lat, start_lng = start_location["lat"], start_location["lng"]

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
Hello,

My name is {{ user_name }} and I am reaching out from PSA. 
We would love to connect with {{ school_email }} about our programs.

Best regards,
{{ user_name }}
{{ user_email }}
"""

@app.route("/api/send-email", methods=["POST"])
@jwt_required()
def send_email():
    app.logger.info("Headers: %s", dict(request.headers))
    app.logger.info("JSON: %s", request.get_json())
    data = request.get_json()
    recipient = data.get("recipient")
    if not recipient:
        return jsonify({"error": "Missing recipient"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.gmail_access_token:
        return jsonify({"error": "User not connected with Gmail"}), 400

    # Render the email body from the template
    body = render_template_string(
        EMAIL_TEMPLATE,
        user_name=user.name,
        user_email=user.email,
        school_email=recipient
    )

    try:
        send_gmail(user, recipient, "Let's Connect! PSA Programs", body)
        return jsonify({"status": "sent"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


