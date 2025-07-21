import os
import requests
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv
import re

# ===== Start Up =====
load_dotenv()  # loads .env

app = Flask(__name__)
CORS(app)

# ===== SQL Database API =====
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'postgresql://postgres.dlnfvtudzyyabixedniz:Pandaplayz6!@aws-0-us-east-1.pooler.supabase.com:6543/postgres'
)
db = SQLAlchemy(app)

# ===== School List API =====
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

@app.route("/api/schools", methods=["GET"])
def get_schools():
    schools = School.query.all()
    return jsonify([
        {"id": s.id, "name": s.name, "address": s.address, "phone": s.phone, "contact": s.contact, "email": s.email}
        for s in schools
    ])

# ===== Utility: Normalize Names =====
def normalize_name(name):
    """Lowercase, remove non-alphanumeric, and extra spaces for fuzzy matching."""
    if not name:
        return ""
    name = name.lower()
    name = re.sub(r'[^a-z0-9 ]', '', name)
    name = re.sub(r'\s+', ' ', name)
    return name.strip()

# ===== School Finder API =====
@app.route("/api/find-schools", methods=["POST"])
def find_schools():
    data = request.get_json()
    address = data.get("address")
    keywords = data.get("keywords", ["school", "kindergarten", "childcare"])
    if not address:
        return jsonify({"error": "No address provided"}), 400

    # Geocode with Nominatim
    lat, lon = geocode_nominatim(address)
    print(f"Geocoded '{address}' to: {lat}, {lon}")
    if lat is None or lon is None:
        print("Nominatim failed to geocode address.")
        return jsonify({"error": "Address not found"}), 404

    osm_schools = find_osm_schools(lat, lon, 5000, keywords)
    print(f"Overpass returned {len(osm_schools)} schools")
    if not osm_schools:
        print("No schools found by Overpass.")
        return jsonify({"error": "No schools found"}), 404

    # Filter out already-partnered schools as before
    happy_feet_names = set([normalize_name(s.name) for s in HappyFeetSchool.query.all()])
    psa_names = set([normalize_name(s.name) for s in PSASchool.query.all()])
    excluded_names = happy_feet_names | psa_names

    schools = []
    for s in osm_schools:
        name = s.get("tags", {}).get("name", "")
        norm_name = normalize_name(name)
        if any(norm_name == ex or norm_name in ex or ex in norm_name for ex in excluded_names):
            continue
        schools.append({
            "name": name,
            "address": s.get("tags", {}).get("addr:full", ""),
            "lat": s["lat"],
            "lng": s["lon"],
            "place_id": str(s["id"])
        })

    return jsonify({
        "schools": schools,
        "location": {"lat": lat, "lng": lon}
    })

def geocode_nominatim(address):
    url = "https://nominatim.openstreetmap.org/search"
    params = {
        "q": address,
        "format": "json",
        "countrycodes": "us",
        "addressdetails": 1,
        "limit": 5
    }
    headers = {"User-Agent": "PSA SchoolFinder/1.0"}
    resp = requests.get(url, params=params, headers=headers)
    data = resp.json()
    # Only accept results that are US postal codes
    for result in data:
        if result.get("type") == "postcode" and result.get("address", {}).get("country_code") == "us":
            return float(result["lat"]), float(result["lon"])
    # fallback to first result if no postal code found
    if data:
        return float(data[0]["lat"]), float(data[0]["lon"])
    return None, None

def find_osm_schools(lat, lon, radius=5000, keywords=None):
    if not keywords:
        keywords = ["school", "kindergarten", "childcare"]
    overpass_url = "https://overpass-api.de/api/interpreter"
    # Query for nodes, ways, and relations
    query = f"""
    [out:json];
    (
      {"".join([f'node["amenity"="{kw}"](around:{radius},{lat},{lon});' for kw in keywords])}
      {"".join([f'way["amenity"="{kw}"](around:{radius},{lat},{lon});' for kw in keywords])}
      {"".join([f'relation["amenity"="{kw}"](around:{radius},{lat},{lon});' for kw in keywords])}
    );
    out center;
    """
    headers = {"User-Agent": "PSA SchoolFinder/1.0"}
    try:
        resp = requests.post(overpass_url, data=query, headers=headers, timeout=30)
        data = resp.json()
        elements = data.get("elements", [])
        print(f"Overpass API success, got {len(elements)} elements")
        # For ways/relations, use 'center' for lat/lon
        for el in elements:
            if el["type"] in ("way", "relation"):
                el["lat"] = el.get("center", {}).get("lat")
                el["lon"] = el.get("center", {}).get("lon")
        # Filter out any without lat/lon (shouldn't happen, but safe)
        elements = [el for el in elements if el.get("lat") is not None and el.get("lon") is not None]
        return elements
    except Exception as e:
        print("Overpass API error:", e)
        return []

# ===== Route Planning API =====
@app.route("/api/route-plan", methods=["POST"])
def route_plan():
    data = request.get_json()
    schools = data.get("schools", [])
    start_address = data.get("start_address")
    if len(schools) < 2:
        return jsonify({"error": "Select at least two schools"}), 400
    if not start_address:
        return jsonify({"error": "No starting address provided"}), 400

    # Geocode start address
    start_lat, start_lon = geocode_nominatim(start_address)
    if start_lat is None or start_lon is None:
        return jsonify({"error": "Starting address not found"}), 404

    waypoints = [(s["lat"], s["lng"]) for s in schools]
    order = osrm_route((start_lat, start_lon), waypoints)
    route = [schools[i]["place_id"] for i in order]
    return jsonify({"route": route})

# ===== OSRM Routing =====
def osrm_route(start, waypoints):
    # start: (lat, lon), waypoints: list of (lat, lon)
    coords = [f"{start[1]},{start[0]}"] + [f"{lon},{lat}" for lat, lon in waypoints]
    coord_str = ";".join(coords)
    url = f"http://router.project-osrm.org/trip/v1/driving/{coord_str}?source=first&roundtrip=false"
    resp = requests.get(url)
    data = resp.json()
    if data["code"] == "Ok":
        # Return the order of waypoints (excluding the start)
        return data["trips"][0]["waypoint_indices"][1:]
    return list(range(len(waypoints)))

try:
    resp = requests.get("https://nominatim.openstreetmap.org/search?q=20120&format=json&countrycodes=us")
    print("Nominatim status code:", resp.status_code)
    print("Nominatim response:", resp.text)
except Exception as e:
    print("Nominatim request failed:", e)