"""School finder v2: parallel Places search, saved-school detection, details, batch save."""

import base64
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from math import isfinite

import requests
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

SEARCH_URL = 'https://maps.googleapis.com/maps/api/place/nearbysearch/json'
DETAILS_URL = 'https://maps.googleapis.com/maps/api/place/details/json'
DEFAULT_KEYWORDS = ['elementary school', 'day care', 'preschool', 'kindercare', 'montessori']
SCHOOL_TYPES = ('preschool', 'elementary', 'private')
DEFAULT_RADIUS_KM = 8
MIN_RADIUS_KM, MAX_RADIUS_KM = 1, 40
MAX_KEYWORDS = 6
MAX_TYPES = 5
SEARCH_WORKERS = 6
DETAILS_WORKERS = 5
MAX_DETAIL_IDS = 20
MAX_SAVE_BATCH = 50
DETAILS_TTL_SECONDS = 24 * 3600
DETAILS_CACHE_MAX = 2000
PAGE_TOKEN_RETRIES = 3
PAGE_TOKEN_DELAY_SECONDS = 2.0
SAME_PLACE_KM = 0.15

_PLACE_ID = re.compile(r'^[A-Za-z0-9_\-]{1,300}$')
_PLACE_TYPE = re.compile(r'^[a-z_]{2,40}$')

_details_cache = {}
_details_lock = threading.Lock()


class SavedIndex:
    """All saved schools, matchable by place_id or by normalised name plus address."""

    def __init__(self, rows, normalize_name, haversine):
        self.normalize_name = normalize_name
        self.haversine = haversine
        self.by_place = {}
        self.by_name = {}
        for row in rows:
            self.add(*row)

    def add(self, school_id, name, address, place_id, lat, lng, owner_id, owner_name):
        entry = {'id': school_id, 'owner_id': owner_id, 'owner_name': owner_name,
                 'address': self.normalize_name(address), 'lat': lat, 'lng': lng}
        if place_id:
            self.by_place.setdefault(place_id, entry)
        key = self.normalize_name(name)
        if key:
            self.by_name.setdefault(key, []).append(entry)

    def match(self, place_id, name, address, lat=None, lng=None):
        if place_id and place_id in self.by_place:
            return self.by_place[place_id]
        wanted_address = self.normalize_name(address)
        for entry in self.by_name.get(self.normalize_name(name), ()):
            have = entry['address']
            if wanted_address and have and (
                    wanted_address == have
                    or (min(len(wanted_address), len(have)) >= 8
                        and (wanted_address.startswith(have) or have.startswith(wanted_address)))):
                return entry
            if (lat is not None and lng is not None and entry['lat'] is not None and entry['lng'] is not None
                    and self.haversine(lat, lng, entry['lat'], entry['lng']) <= SAME_PLACE_KM):
                return entry
        return None


def load_saved_index(db, SalesSchool, User, normalize_name, haversine):
    rows = db.session.query(
        SalesSchool.id, SalesSchool.school_name, SalesSchool.address, SalesSchool.place_id,
        SalesSchool.lat, SalesSchool.lng, SalesSchool.user_id, User.name).join(
        User, User.id == SalesSchool.user_id).all()
    return SavedIndex([tuple(row) for row in rows], normalize_name, haversine)


def valid_coordinate(value, bound):
    return type(value) in (int, float) and isfinite(value) and abs(value) <= bound


def encode_page_token(payload):
    raw = json.dumps(payload, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def decode_page_token(token):
    try:
        payload = json.loads(base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)))
        tasks = payload['t']
        if (not isinstance(tasks, list) or not 1 <= len(tasks) <= MAX_KEYWORDS * MAX_TYPES
                or not valid_coordinate(payload['lat'], 90) or not valid_coordinate(payload['lng'], 180)
                or not valid_coordinate(payload['r'], 100) or not isinstance(payload.get('label', ''), str)):
            raise ValueError
        for item in tasks:
            if (not isinstance(item, list) or len(item) != 3
                    or not all(isinstance(part, str) and 0 < len(part) <= 1500 for part in item)):
                raise ValueError
        return payload
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return None


def parse_keywords(value):
    """Return (keywords, error)."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return list(DEFAULT_KEYWORDS), None
    if isinstance(value, str):
        value = [part.strip() for part in re.split(r'[,;\n]', value) if part.strip()]
    if (not isinstance(value, list) or not 1 <= len(value) <= MAX_KEYWORDS
            or any(not isinstance(item, str) or not item.strip() or len(item) > 60 for item in value)):
        return None, 'Choose between 1 and 6 school search terms'
    cleaned = []
    for item in value:
        item = item.strip()
        if item.lower() not in [seen.lower() for seen in cleaned]:
            cleaned.append(item)
    return cleaned, None


def clean_text(value, limit):
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:limit] if value else None


def register_finder_routes(app, db, SalesSchool, User, hooks):
    """hooks: normalize_name, haversine, geocode(address), google_key(), partner_names(),
    school_conflict(name, address, emails, candidates), valid_email(text), sleep(seconds)."""

    def current_user():
        try:
            return db.session.get(User, int(get_jwt_identity()))
        except (TypeError, ValueError):
            return None

    def provider_get(url, params):
        """One provider call; returns parsed JSON or None. Never logs the URL or key."""
        try:
            response = requests.get(url, params=params, timeout=12)
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            app.logger.warning('Places request failed: %s', type(exc).__name__)
            return None
        return body if isinstance(body, dict) else None

    def search_one(task, lat, lng, radius_m):
        keyword, place_type, page_token = task
        key = hooks.google_key()
        if page_token:
            params = {'pagetoken': page_token, 'key': key}
        else:
            params = {'location': f'{lat},{lng}', 'radius': radius_m, 'type': place_type,
                      'keyword': keyword, 'key': key}
        body = None
        for attempt in range(PAGE_TOKEN_RETRIES if page_token else 1):
            body = provider_get(SEARCH_URL, params)
            if body is None:
                break
            if page_token and body.get('status') == 'INVALID_REQUEST' and attempt < PAGE_TOKEN_RETRIES - 1:
                hooks.sleep(PAGE_TOKEN_DELAY_SECONDS)  # a fresh token needs a moment to activate
                continue
            break
        if body is None or body.get('status', 'OK') not in ('OK', 'ZERO_RESULTS'):
            return None
        return {'results': body.get('results') or [], 'next': body.get('next_page_token'),
                'keyword': keyword, 'type': place_type}

    @app.route('/api/find-schools', methods=['POST'])
    @jwt_required()
    def find_schools():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error='Enter a search location'), 400
        keywords, error = parse_keywords(data.get('keywords'))
        if error:
            return jsonify(error=error), 400
        types = data.get('types')
        if types in (None, []):
            types = ['school']
        if (not isinstance(types, list) or len(types) > MAX_TYPES
                or any(not isinstance(item, str) or not _PLACE_TYPE.match(item) for item in types)):
            return jsonify(error='Choose up to 5 valid place types'), 400
        radius = data.get('radius_km', DEFAULT_RADIUS_KM)
        if radius is None:
            radius = DEFAULT_RADIUS_KM
        if type(radius) not in (int, float) or not isfinite(radius):
            return jsonify(error='Enter a radius between 1 and 40 km'), 400
        radius = min(max(radius, MIN_RADIUS_KM), MAX_RADIUS_KM)
        raw_token = data.get('page_token')
        if raw_token is not None and (not isinstance(raw_token, str) or len(raw_token) > 20000):
            return jsonify(error='Invalid page token'), 400
        lat, lng = data.get('lat'), data.get('lng')
        have_point = lat is not None or lng is not None
        if have_point and not (valid_coordinate(lat, 90) and valid_coordinate(lng, 180)):
            return jsonify(error='Enter a valid latitude and longitude'), 400
        address = data.get('address')
        if address is not None and (not isinstance(address, str) or len(address) > 500):
            return jsonify(error='No address provided'), 400
        address = (address or '').strip()
        token = None
        if raw_token:
            token = decode_page_token(raw_token)
            if token is None:
                return jsonify(error='Invalid page token'), 400
        elif not have_point and not address:
            return jsonify(error='No address provided'), 400

        # Partner lists load on demand so a Sheets outage cannot stop the API at startup.
        try:
            excluded_names = hooks.partner_names()
        except Exception:
            app.logger.exception('Could not load partner schools for Finder')
            return jsonify(error='Partner school list is temporarily unavailable. Try again shortly.'), 503

        if token:
            lat, lng, radius, label = token['lat'], token['lng'], token['r'], token.get('label') or ''
            tasks = [tuple(item) for item in token['t']]
        else:
            if have_point:
                label = address or f'{lat:.4f}, {lng:.4f}'
            else:
                label = address
                query = address
                # A bare ZIP code or city name geocodes more reliably with the country.
                if re.fullmatch(r'\d{5}', query) or re.fullmatch(r'[a-zA-Z ]+', query):
                    query = f'{query} USA'
                lat, lng = hooks.geocode(query)
                if lat is None or lng is None:
                    return jsonify(error='Address not found'), 404
            tasks = [(keyword, place_type, None) for place_type in types for keyword in keywords]

        radius_m = int(round(radius * 1000))
        with ThreadPoolExecutor(max_workers=min(SEARCH_WORKERS, len(tasks))) as pool:
            outcomes = list(pool.map(lambda task: search_one(task, lat, lng, radius_m), tasks))
        succeeded = [item for item in outcomes if item is not None]
        if not succeeded:
            return jsonify(error='School search is temporarily unavailable. Please try again.'), 502

        unique = {}
        for outcome in succeeded:
            for result in outcome['results']:
                place_id = result.get('place_id')
                if place_id and place_id not in unique:
                    unique[place_id] = result
        next_tasks = [[item['keyword'], item['type'], item['next']] for item in succeeded if item.get('next')]
        next_token = encode_page_token({'lat': lat, 'lng': lng, 'r': radius, 'label': label, 't': next_tasks}) \
            if next_tasks else None

        viewer = current_user()
        index = load_saved_index(db, SalesSchool, User, hooks.normalize_name, hooks.haversine)
        schools = []
        for place_id, result in unique.items():
            location = (result.get('geometry') or {}).get('location') or {}
            place_lat, place_lng = location.get('lat'), location.get('lng')
            if not valid_coordinate(place_lat, 90) or not valid_coordinate(place_lng, 180):
                continue
            name = result.get('name') or ''
            normalized_name = hooks.normalize_name(name)
            if any(normalized_name == ex or normalized_name in ex or ex in normalized_name
                   for ex in excluded_names):
                continue
            address_text = result.get('vicinity') or result.get('formatted_address')
            saved = index.match(place_id, name, address_text, place_lat, place_lng)
            can_open = bool(saved and viewer and (viewer.admin or saved['owner_id'] == viewer.id))
            schools.append({
                'place_id': place_id, 'school_name': name, 'name': name, 'address': address_text,
                'lat': place_lat, 'lng': place_lng,
                'distance_km': round(hooks.haversine(lat, lng, place_lat, place_lng), 2),
                'rating': result.get('rating'),
                'user_ratings_total': result.get('user_ratings_total'),
                'types': result.get('types') or [],
                'already_saved': bool(saved),
                'saved_school_id': saved['id'] if can_open else None,
                'owner_name': saved['owner_name'] if saved else None,
                # Kept for clients built against the first finder.
                'assigned': bool(saved),
                'sales_school_id': saved['id'] if can_open else None,
            })
        schools.sort(key=lambda item: (item['distance_km'], item['school_name'].lower()))
        return jsonify(location={'lat': lat, 'lng': lng, 'label': label}, radius_km=radius,
                       schools=schools, next_page_token=next_token)

    def fetch_details(place_id):
        now = time.monotonic()
        with _details_lock:
            hit = _details_cache.get(place_id)
            if hit and hit[0] > now:
                return place_id, hit[1]
        body = provider_get(DETAILS_URL, {
            'place_id': place_id, 'key': hooks.google_key(),
            'fields': 'formatted_phone_number,international_phone_number,website,opening_hours,formatted_address'})
        if body is None or body.get('status', 'OK') != 'OK':
            return place_id, None
        result = body.get('result') or {}
        hours = (result.get('opening_hours') or {}).get('weekday_text') or []
        detail = {
            'phone': result.get('formatted_phone_number') or result.get('international_phone_number'),
            'website': result.get('website'),
            'hours_text': '; '.join(item for item in hours if isinstance(item, str)) or None,
            'formatted_address': result.get('formatted_address'),
        }
        with _details_lock:
            if len(_details_cache) >= DETAILS_CACHE_MAX:
                for stale in sorted(_details_cache, key=lambda item: _details_cache[item][0])[:DETAILS_CACHE_MAX // 4]:
                    _details_cache.pop(stale, None)
            _details_cache[place_id] = (now + DETAILS_TTL_SECONDS, detail)
        return place_id, detail

    @app.route('/api/find-schools/details', methods=['POST'])
    @jwt_required()
    def find_school_details():
        data = request.get_json(silent=True)
        ids = data.get('place_ids') if isinstance(data, dict) else None
        if (not isinstance(ids, list) or not 1 <= len(ids) <= MAX_DETAIL_IDS
                or any(not isinstance(item, str) or not _PLACE_ID.match(item) for item in ids)):
            return jsonify(error='Supply between 1 and 20 place identifiers'), 400
        ids = list(dict.fromkeys(ids))
        with ThreadPoolExecutor(max_workers=min(DETAILS_WORKERS, len(ids))) as pool:
            fetched = list(pool.map(fetch_details, ids))
        details = {place_id: detail for place_id, detail in fetched if detail is not None}
        if not details:
            return jsonify(error='Place details are temporarily unavailable. Please try again.'), 502
        return jsonify(details=details)

    @app.route('/api/find-schools/save-batch', methods=['POST'])
    @jwt_required()
    def save_found_schools():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        data = request.get_json(silent=True)
        items = data.get('schools') if isinstance(data, dict) else None
        if not isinstance(items, list) or not 1 <= len(items) <= MAX_SAVE_BATCH:
            return jsonify(error='Select between 1 and 50 schools'), 400
        owner = user
        if data.get('assign_to') is not None:
            target = data['assign_to']
            if target != user.id:
                if not user.admin:
                    return jsonify(error='Only administrators can assign schools to teammates'), 403
                owner = db.session.get(User, target) if type(target) is int else None
                if not owner:
                    return jsonify(error='Employee not found'), 400

        index = load_saved_index(db, SalesSchool, User, hooks.normalize_name, hooks.haversine)
        candidates = None  # loaded only when a school carries an email address
        created, skipped = [], []
        for item in items:
            place_id = item.get('place_id') if isinstance(item, dict) else None
            if not isinstance(item, dict) or not isinstance(place_id, str) or not place_id.strip():
                skipped.append({'place_id': place_id if isinstance(place_id, str) else None, 'reason': 'invalid'})
                continue
            place_id = place_id.strip()
            name = clean_text(item.get('school_name'), 200)
            if not name:
                skipped.append({'place_id': place_id, 'reason': 'invalid'})
                continue
            address = clean_text(item.get('address'), 500)
            lat, lng = item.get('lat'), item.get('lng')
            if lat is not None or lng is not None:
                if not (valid_coordinate(lat, 90) and valid_coordinate(lng, 180)):
                    skipped.append({'place_id': place_id, 'reason': 'invalid'})
                    continue
            school_type = item.get('school_type') or 'preschool'
            if school_type not in SCHOOL_TYPES:
                skipped.append({'place_id': place_id, 'reason': 'invalid'})
                continue
            raw_email = item.get('email')
            email = raw_email.strip() if isinstance(raw_email, str) else ''
            if (raw_email is not None and not isinstance(raw_email, str)) or (email and not hooks.valid_email(email)):
                skipped.append({'place_id': place_id, 'reason': 'invalid'})
                continue
            existing = index.match(place_id, name, address, lat, lng)
            if not existing and email:
                if candidates is None:
                    candidates = SalesSchool.query.all()
                clash = hooks.school_conflict(name, address, [email], candidates)
                if clash:
                    existing = {'id': clash.id, 'owner_id': clash.user_id, 'owner_name': clash.user.name}
            if existing:
                skipped.append({
                    'place_id': place_id, 'reason': 'duplicate',
                    'detail': f"Already assigned to {existing['owner_name']}",
                    'owner_name': existing['owner_name'], 'existing_id': existing['id']})
                continue
            website = clean_text(item.get('website'), 500)
            school = SalesSchool(
                school_name=name, email=email, phone=clean_text(item.get('phone'), 50), address=address,
                school_type=school_type, user_id=owner.id, place_id=place_id,
                lat=lat, lng=lng, website=website)
            db.session.add(school)
            db.session.flush()
            index.add(school.id, name, address, place_id, lat, lng, owner.id, owner.name)
            if candidates is not None:
                candidates.append(school)
            created.append({'place_id': place_id, 'id': school.id})
        db.session.commit()
        return jsonify(created=created, skipped=skipped)
