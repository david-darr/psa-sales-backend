"""Closed-won accounts: stage rules, rep portfolio, and map data.

Closed won means status 'partner' (active client) or 'former' (was a client,
no longer active). Visibility follows the CRM rule: administrators see every
rep, everyone else sees only their own schools.
"""

import re
import time
from datetime import datetime, timedelta, timezone

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import func

STAGES = ('pending', 'contacted', 'replied', 'meeting', 'partner', 'former', 'not_interested')
CLOSED_STAGES = ('partner', 'former')
PIPELINE_STAGES = ('pending', 'contacted', 'replied', 'meeting')
# Stages where the conversation is over: no follow-up reminders.
FINISHED_STAGES = ('partner', 'former', 'not_interested')

LOCATE_DEFAULT_LIMIT = 25
LOCATE_MAX_LIMIT = 50
LOCATE_TIME_BUDGET_SECONDS = 25
NEGATIVE_CACHE_WINDOW = timedelta(hours=1)


def utc_aware_now():
    return datetime.now(timezone.utc)


def as_aware(value):
    """Treat naive database timestamps as UTC."""
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def iso_utc(value):
    value = as_aware(value)
    return value.isoformat() if value else None


def set_school_status(school, status, actor_id=None):
    """Change a school's stage and stamp closed_at/closed_by the first time it closes.

    Moving partner -> former keeps the original close date, and an existing
    closed_at is never overwritten. Returns True when the stage changed.
    """
    changed = school.status != status
    school.status = status
    if status in CLOSED_STAGES and school.closed_at is None:
        school.closed_at = utc_aware_now()
        school.closed_by_id = actor_id
    return changed


def initials(name):
    parts = [part for part in re.split(r'\s+', (name or '').strip()) if part]
    if not parts:
        return '?'
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


_STATE_ZIP = re.compile(r'^[A-Za-z]{2}(\s+\d{5}(-\d{4})?)?$')


def city_from_address(address):
    """Best effort city from 'street, city, ST zip' style addresses."""
    parts = [part.strip() for part in (address or '').split(',') if part.strip()]
    if parts and parts[-1].lower() in ('usa', 'us', 'united states'):
        parts.pop()
    popped_state = False
    if parts and _STATE_ZIP.match(parts[-1]):
        parts.pop()
        popped_state = True
    if not parts:
        return None
    if popped_state or len(parts) >= 2:
        return parts[-1]
    return None


def scope_query(query, model, user):
    if not user.admin or request.args.get('scope') == 'mine':
        query = query.filter(model.user_id == user.id)
    return query


def parse_stage_list(raw, default):
    if raw is None or not raw.strip():
        return list(default)
    stages = []
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        if item not in STAGES:
            raise ValueError('Invalid school stage')
        if item not in stages:
            stages.append(item)
    return stages or list(default)


def register_portfolio_routes(app, db, User, School, Activity, SentEmail, GeocodedAddress, hooks):
    """hooks needs: normalize_name(text) and geocode(address) -> (lat, lng)."""

    def current_user():
        return db.session.get(User, int(get_jwt_identity()))

    def cached_coords(addresses):
        """Saved geocoder coordinates keyed by normalised address (any age)."""
        keys = {hooks.normalize_name(item) for item in addresses if item}
        keys.discard('')
        found = {}
        keys = list(keys)
        for start in range(0, len(keys), 500):
            for row in GeocodedAddress.query.filter(
                    GeocodedAddress.address_key.in_(keys[start:start + 500]),
                    GeocodedAddress.lat.isnot(None), GeocodedAddress.lng.isnot(None)).all():
                found[row.address_key] = (row.lat, row.lng)
        return found

    def resolve_coords(lat, lng, address, cache):
        if lat is not None and lng is not None:
            return lat, lng
        return cache.get(hooks.normalize_name(address), (None, None)) if address else (None, None)

    @app.get('/api/crm/portfolio')
    @jwt_required()
    def crm_portfolio():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        all_scope = bool(user.admin and request.args.get('scope') != 'mine')

        users = User.query.order_by(User.name, User.id)
        if not all_scope:
            users = users.filter(User.id == user.id)
        users = users.all()

        counts = {}
        status_rows = scope_query(db.session.query(School.user_id, School.status, func.count(School.id)),
                                  School, user).group_by(School.user_id, School.status).all()
        for owner_id, status, count in status_rows:
            counts.setdefault(owner_id, {})[status or 'pending'] = count

        closed_rows = scope_query(db.session.query(
            School.id, School.user_id, School.school_name, School.status, School.school_type,
            School.address, School.lat, School.lng, School.closed_at, School.contact_name,
            School.created_at), School, user).filter(School.status.in_(CLOSED_STAGES)).all()

        ids = [row.id for row in closed_rows]
        last_seen = {}
        if ids:
            def note(school_id, moment):
                moment = as_aware(moment)
                if moment and (school_id not in last_seen or moment > last_seen[school_id]):
                    last_seen[school_id] = moment
            for school_id, moment in db.session.query(
                    Activity.sales_school_id, func.max(Activity.created_at)).filter(
                    Activity.sales_school_id.in_(ids)).group_by(Activity.sales_school_id).all():
                note(school_id, moment)
            for school_id, sent, replied in db.session.query(
                    SentEmail.sales_school_id, func.max(SentEmail.sent_at),
                    func.max(SentEmail.last_reply_date)).filter(
                    SentEmail.sales_school_id.in_(ids)).group_by(SentEmail.sales_school_id).all():
                note(school_id, sent)
                note(school_id, replied)
        cache = cached_coords([row.address for row in closed_rows if row.lat is None or row.lng is None])

        cutoff = utc_aware_now() - timedelta(days=90)
        floor = datetime.min.replace(tzinfo=timezone.utc)
        by_owner = {}
        for row in closed_rows:
            by_owner.setdefault(row.user_id, []).append(row)

        reps = []
        for rep in users:
            own = by_owner.get(rep.id, [])
            own.sort(key=lambda row: (as_aware(row.closed_at) or floor, row.id), reverse=True)
            status_counts = counts.get(rep.id, {})
            active = status_counts.get('partner', 0)
            former = status_counts.get('former', 0)
            pipeline = sum(status_counts.get(stage, 0) for stage in PIPELINE_STAGES)
            accounts = []
            for row in own:
                lat, lng = resolve_coords(row.lat, row.lng, row.address, cache)
                accounts.append({
                    'id': row.id, 'school_name': row.school_name, 'status': row.status,
                    'school_type': row.school_type, 'address': row.address,
                    'city': city_from_address(row.address), 'lat': lat, 'lng': lng,
                    'closed_at': iso_utc(row.closed_at),
                    'last_activity_at': iso_utc(last_seen.get(row.id)),
                    'contact_name': row.contact_name,
                })
            reps.append({
                'id': rep.id, 'name': rep.name, 'email': rep.email, 'admin': bool(rep.admin),
                'initials': initials(rep.name),
                'counts': {'total': sum(status_counts.values()), 'pipeline': pipeline,
                           'active': active, 'former': former},
                'closed_last_90': sum(1 for row in own if row.closed_at and as_aware(row.closed_at) >= cutoff),
                'closed_total': len(own),
                'accounts': accounts,
            })
        reps.sort(key=lambda rep: (-rep['counts']['active'], (rep['name'] or '').lower(), rep['id']))
        return jsonify(
            scope='all' if all_scope else 'self',
            totals={
                'reps': len(reps),
                'total_schools': sum(rep['counts']['total'] for rep in reps),
                'active_clients': sum(rep['counts']['active'] for rep in reps),
                'former_clients': sum(rep['counts']['former'] for rep in reps),
                'in_pipeline': sum(rep['counts']['pipeline'] for rep in reps),
                'closed_last_90': sum(rep['closed_last_90'] for rep in reps),
            },
            reps=reps,
        )

    @app.get('/api/crm/map-accounts')
    @jwt_required()
    def crm_map_accounts():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        try:
            stages = parse_stage_list(request.args.get('stages'), CLOSED_STAGES)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        owner = request.args.get('owner')
        owner_id = None
        if owner:
            try:
                owner_id = int(owner)
            except ValueError:
                return jsonify(error='Invalid owner'), 400
        rows = scope_query(db.session.query(
            School.id, School.school_name, School.address, School.status, School.school_type,
            School.user_id, User.name, School.lat, School.lng, School.closed_at).join(
            User, User.id == School.user_id), School, user).filter(
            School.status.in_(stages)).order_by(School.id).all()

        rep_counts = {}
        for row in rows:
            entry = rep_counts.setdefault(row.user_id, {'id': row.user_id, 'name': row[6], 'count': 0})
            entry['count'] += 1
        reps = sorted(rep_counts.values(), key=lambda rep: (-rep['count'], (rep['name'] or '').lower(), rep['id']))

        if owner_id is not None:
            rows = [row for row in rows if row.user_id == owner_id]
        cache = cached_coords([row.address for row in rows if row.lat is None or row.lng is None])
        accounts, unlocated = [], 0
        for row in rows:
            lat, lng = resolve_coords(row.lat, row.lng, row.address, cache)
            if lat is None or lng is None:
                unlocated += 1
                continue
            accounts.append({
                'id': row.id, 'school_name': row.school_name, 'address': row.address,
                'status': row.status, 'school_type': row.school_type, 'owner_id': row.user_id,
                'owner_name': row[6], 'lat': lat, 'lng': lng, 'closed_at': iso_utc(row.closed_at),
            })
        return jsonify(accounts=accounts, reps=reps, unlocated=unlocated)

    @app.post('/api/crm/map-accounts/locate')
    @jwt_required()
    def crm_locate_accounts():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        data = request.get_json(silent=True)
        if data is None:
            data = {}
        if not isinstance(data, dict):
            return jsonify(error='Supply a limit'), 400
        limit = data.get('limit', LOCATE_DEFAULT_LIMIT)
        if type(limit) is not int or limit < 1:
            return jsonify(error='Limit must be a positive whole number'), 400
        limit = min(limit, LOCATE_MAX_LIMIT)

        missing = scope_query(db.session.query(School.id, School.address), School, user).filter(
            (School.lat.is_(None)) | (School.lng.is_(None)),
            School.address.isnot(None), School.address != '').order_by(School.id).all()
        missing = [(school_id, address) for school_id, address in missing if (address or '').strip()]
        keys = {school_id: hooks.normalize_name(address) for school_id, address in missing}
        entries = {}
        distinct = list({key for key in keys.values() if key})
        for start in range(0, len(distinct), 500):
            for row in GeocodedAddress.query.filter(
                    GeocodedAddress.address_key.in_(distinct[start:start + 500])).all():
                entries[row.address_key] = row

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        pending = []
        for school_id, address in missing:
            entry = entries.get(keys[school_id])
            if entry is not None and entry.lat is None and entry.checked_at \
                    and entry.checked_at >= now - NEGATIVE_CACHE_WINDOW:
                continue  # already tried a moment ago; do not loop on it
            pending.append((school_id, address))

        started = time.monotonic()
        resolved = {}
        handled = located = 0
        batch = pending[:limit]
        schools = {row.id: row for row in School.query.filter(
            School.id.in_([school_id for school_id, _ in batch])).all()} if batch else {}
        for school_id, address in batch:
            if time.monotonic() - started > LOCATE_TIME_BUDGET_SECONDS:
                break
            key = keys[school_id]
            if key in resolved:
                lat, lng = resolved[key]
            else:
                entry = entries.get(key)
                if entry is not None and entry.lat is not None and entry.lng is not None:
                    lat, lng = entry.lat, entry.lng
                else:
                    lat, lng = hooks.geocode(address)
                    if lat is None or lng is None:
                        lat, lng = None, None
                        if key not in entries and key:
                            existing = db.session.get(GeocodedAddress, key)
                            if existing is None:
                                note = GeocodedAddress(address_key=key, lat=None, lng=None, checked_at=now)
                                db.session.add(note)
                                entries[key] = note
                resolved[key] = (lat, lng)
            handled += 1
            if lat is not None and lng is not None and school_id in schools:
                schools[school_id].lat, schools[school_id].lng = lat, lng
                located += 1
        db.session.commit()
        return jsonify(located=located, remaining=max(len(pending) - handled, 0))
