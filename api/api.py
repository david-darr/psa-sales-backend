import os
import requests
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv
import re
from itertools import permutations
from math import radians, cos, sin, sqrt, atan2
import gspread
import json
from oauth2client.service_account import ServiceAccountCredentials



# ===== Start Up =====
load_dotenv() # loads .env
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

app = Flask(__name__)
CORS(app)



# ===== SQL Database API =====
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'postgresql://postgres.dlnfvtudzyyabixedniz:Pandaplayz6!@aws-0-us-east-1.pooler.supabase.com:6543/postgres'
)
db = SQLAlchemy(app)


# === Global variable to store all sheets data ===
ALL_SHEET_DATA = {}

def load_all_sheets():
    scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
    service_account_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    service_account_info = json.loads(service_account_json)
    # Always replace double-escaped newlines with real newlines
    service_account_info["private_key"] = service_account_info["private_key"].replace("\\n", "\n")
    creds = ServiceAccountCredentials.from_json_keyfile_dict(service_account_info, scope)
    client = gspread.authorize(creds)
    sheet = client.open('PSA sales from Scratch')

    all_data = {}
    for worksheet in sheet.worksheets():
        # Get all values as a list of rows
        rows = worksheet.get_all_values()
        all_data[worksheet.title] = rows
    return all_data

# Load all sheets into memory at startup
ALL_SHEET_DATA = load_all_sheets()

GENERIC_NAMES = {"elementary", "preschool", "school name", "elementary school"}

def get_all_sheet_school_names():
    excluded_names = set()
    for sheet_rows in ALL_SHEET_DATA.values():
        for row in sheet_rows:
            if row and row[0]:
                norm = normalize_name(row[0])
                if norm not in GENERIC_NAMES:
                    excluded_names.add(norm)
    return excluded_names

@app.route("/api/team-sheets", methods=["GET"])
def get_team_sheets():
    # Returns all sheet data for frontend display
    return jsonify(load_all_sheets())


# ===== School List API =====
class School(db.Model):
    __tablename__ = 'schools'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    address = db.Column(db.String, nullable=False)
    phone = db.Column(db.String, nullable=False)
    contact = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)

# Add models for the two other tables
class HappyFeetSchool(db.Model):
    __tablename__ = 'Happy Feet Schools'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)

class PSASchool(db.Model):
    __tablename__ = 'PSA Schools'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)

@app.route("/api/schools", methods=["GET"])
def get_schools():
    schools = School.query.all()
    return jsonify([
        {"id": s.id, "name": s.name, "address": s.address, "phone": s.phone, "contact": s.contact, "email": s.email}
        for s in schools
    ])


# ===== School Finder API =====
def normalize_name(name):
    """Lowercase, remove non-alphanumeric, and extra spaces for fuzzy matching."""
    if not name:
        return ""
    name = name.lower()
    name = re.sub(r'[^a-z0-9 ]', '', name)
    name = re.sub(r'\s+', ' ', name)
    return name.strip()

@app.route("/api/find-schools", methods=["POST"])
def find_schools():
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
        # Exact or very close match (allow for minor variations)
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


# ===== Route Planning API =====
def haversine(lat1, lng1, lat2, lng2):
    # Calculate the great-circle distance between two points
    R = 6371  # Earth radius in km
    dlat = radians(lat2 - lat1)
    dlng = radians(lng2 - lng1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlng/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

@app.route("/api/route-plan", methods=["POST"])
def route_plan():
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
    from itertools import permutations
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


