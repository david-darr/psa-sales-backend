"""Administrator-only sales controls: commissions, deal closes and rep join links.

Commission for one rep on one closed school is
    deal_value * share_pct / 100 * rate_pct / 100
where rate_pct falls back to the rep's default commission_rate. A school with no
split rows pays its closer (or owner, if no closer was recorded) a 100% share.
"""

import csv
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from io import StringIO

from flask import Response, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy.orm import joinedload

from .portfolio import CLOSED_STAGES, as_aware, iso_utc, set_school_status

JOIN_LINK_DAYS = (1, 7, 14, 30)
CENT = Decimal('0.01')


def hash_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def naive_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def money(value):
    return float(Decimal(value).quantize(CENT)) if value is not None else None


def percent(value, field):
    """Parse a 0-100 percentage; None stays None."""
    if value is None or value == '':
        return None
    if isinstance(value, bool):
        raise ValueError(f'{field} must be a number')
    try:
        number = Decimal(str(value))
    except InvalidOperation:
        raise ValueError(f'{field} must be a number')
    if not number.is_finite() or number < 0 or number > 100:
        raise ValueError(f'{field} must be between 0 and 100')
    return number.quantize(CENT)


def parse_day(value, field):
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise ValueError(f'{field} must be a date like 2026-10-29')


def usable_join_link(model, token, lock=False):
    """The link for this token if it can still create an account, else None."""
    if not isinstance(token, str) or not token or len(token) > 256:
        return None
    query = model.query.filter_by(token_hash=hash_token(token))
    if lock:
        query = query.with_for_update()
    link = query.first()
    if (not link or link.revoked_at or link.expires_at <= naive_utc()
            or (link.max_uses is not None and link.use_count >= link.max_uses)):
        return None
    return link


def register_admin_sales_routes(app, db, User, School, Split, JoinLink, Activity):
    def current_admin():
        user = db.session.get(User, int(get_jwt_identity()))
        return user if user and user.admin else None

    def forbidden():
        return jsonify(error='Administrator access required'), 403

    def earners(school, splits_by_school, reps):
        """[(rep, share, rate)] for a closed school."""
        rows = splits_by_school.get(school.id)
        if rows:
            return [(reps.get(row.user_id), Decimal(row.share_pct),
                     Decimal(row.rate_pct) if row.rate_pct is not None else None) for row in rows]
        closer = reps.get(school.closed_by_id) or reps.get(school.user_id)
        return [(closer, Decimal(100), None)]

    def close_dict(school, splits_by_school, reps):
        lines = []
        for rep, share, rate in earners(school, splits_by_school, reps):
            effective = rate if rate is not None else (
                Decimal(rep.commission_rate) if rep and rep.commission_rate is not None else None)
            amount = None
            if school.deal_value is not None and effective is not None:
                amount = Decimal(school.deal_value) * share / 100 * effective / 100
            lines.append({
                'user_id': rep.id if rep else None, 'name': rep.name if rep else 'Former rep',
                'share_pct': float(share), 'rate_pct': float(rate) if rate is not None else None,
                'effective_rate_pct': float(effective) if effective is not None else None,
                'commission': money(amount),
            })
        return {
            'id': school.id, 'school_name': school.school_name, 'status': school.status,
            'owner_id': school.user_id, 'owner_name': school.user.name if school.user else None,
            'closed_at': iso_utc(school.closed_at), 'closed_by_id': school.closed_by_id,
            'closed_by_name': school.closed_by.name if school.closed_by else None,
            'deal_value': money(school.deal_value), 'custom_split': bool(splits_by_school.get(school.id)),
            'needs_review': school.deal_value is None or any(line['effective_rate_pct'] is None for line in lines),
            'earners': lines,
        }

    def commission_report():
        start = parse_day(request.args.get('from'), 'From')
        end = parse_day(request.args.get('to'), 'To')
        if start and end and end < start:
            raise ValueError('The end date is before the start date')
        reps = {rep.id: rep for rep in User.query.order_by(User.name, User.id).all()}
        query = School.query.options(joinedload(School.user), joinedload(School.closed_by)).filter(
            School.status.in_(CLOSED_STAGES))
        schools = []
        for school in query.order_by(School.closed_at.desc().nullslast(), School.id).all():
            closed = as_aware(school.closed_at)
            if start and (closed is None or closed < start):
                continue
            if end and (closed is None or closed >= end + timedelta(days=1)):
                continue
            schools.append(school)
        splits_by_school = {}
        if schools:
            for row in Split.query.filter(Split.sales_school_id.in_([s.id for s in schools])).order_by(Split.id).all():
                splits_by_school.setdefault(row.sales_school_id, []).append(row)
        closes = [close_dict(school, splits_by_school, reps) for school in schools]

        totals = {rep_id: {'closes': 0, 'deal_value': Decimal(0), 'commission': Decimal(0)} for rep_id in reps}
        for close in closes:
            for line in close['earners']:
                if line['user_id'] not in totals:
                    continue
                entry = totals[line['user_id']]
                entry['closes'] += 1
                if close['deal_value'] is not None:
                    entry['deal_value'] += Decimal(str(close['deal_value'])) * Decimal(str(line['share_pct'])) / 100
                if line['commission'] is not None:
                    entry['commission'] += Decimal(str(line['commission']))
        rep_rows = [{
            'id': rep.id, 'name': rep.name, 'email': rep.email, 'admin': bool(rep.admin),
            'commission_rate': float(rep.commission_rate) if rep.commission_rate is not None else None,
            'closes': totals[rep.id]['closes'], 'credited_value': money(totals[rep.id]['deal_value']),
            'commission': money(totals[rep.id]['commission']),
        } for rep in reps.values()]
        summary = {
            'closes': len(closes),
            'deal_value': money(sum((Decimal(str(c['deal_value'])) for c in closes if c['deal_value'] is not None), Decimal(0))),
            'commission': money(sum((Decimal(str(r['commission'])) for r in rep_rows), Decimal(0))),
            'needs_review': sum(1 for close in closes if close['needs_review']),
        }
        return rep_rows, closes, summary

    @app.get('/api/admin/commissions')
    @jwt_required()
    def admin_commissions():
        if not current_admin():
            return forbidden()
        try:
            reps, closes, summary = commission_report()
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        if request.args.get('format') == 'csv':
            out = StringIO()
            writer = csv.writer(out)
            writer.writerow(['School', 'Stage', 'Closed', 'Deal value', 'Rep', 'Share %', 'Rate %', 'Commission'])
            for close in closes:
                for line in close['earners']:
                    writer.writerow([close['school_name'], close['status'], (close['closed_at'] or '')[:10],
                                     close['deal_value'] if close['deal_value'] is not None else '',
                                     line['name'], line['share_pct'],
                                     line['effective_rate_pct'] if line['effective_rate_pct'] is not None else '',
                                     line['commission'] if line['commission'] is not None else ''])
            return Response(out.getvalue(), mimetype='text/csv',
                            headers={'Content-Disposition': 'attachment; filename="psa-commissions.csv"'})
        return jsonify(reps=reps, closes=closes, summary=summary)

    @app.patch('/api/admin/reps/<int:rep_id>')
    @jwt_required()
    def admin_update_rep(rep_id):
        if not current_admin():
            return forbidden()
        rep = db.session.get(User, rep_id)
        if not rep:
            return jsonify(error='Rep not found'), 404
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != {'commission_rate'}:
            return jsonify(error='Supply commission_rate'), 400
        try:
            rep.commission_rate = percent(data['commission_rate'], 'Commission rate')
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        db.session.commit()
        return jsonify(id=rep.id, commission_rate=float(rep.commission_rate) if rep.commission_rate is not None else None)

    @app.put('/api/admin/schools/<int:school_id>/close')
    @jwt_required()
    def admin_record_close(school_id):
        """Record or correct a close: stage, deal value, closer, date and commission split."""
        admin = current_admin()
        if not admin:
            return forbidden()
        school = School.query.filter_by(id=school_id).with_for_update().first()
        if not school:
            return jsonify(error='School not found'), 404
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error='Supply the close details'), 400
        status = data.get('status', school.status if school.status in CLOSED_STAGES else 'partner')
        if status not in CLOSED_STAGES:
            return jsonify(error='A close must be Active client or Former client'), 400
        deal_value = data.get('deal_value')
        if deal_value is not None:
            try:
                deal_value = Decimal(str(deal_value))
            except InvalidOperation:
                return jsonify(error='Deal value must be a number'), 400
            if isinstance(data.get('deal_value'), bool) or not deal_value.is_finite() or deal_value < 0 \
                    or deal_value >= Decimal('10000000000'):
                return jsonify(error='Deal value must be zero or more'), 400
        closed_by_id = data.get('closed_by_id', school.closed_by_id or school.user_id)
        if type(closed_by_id) is not int or not db.session.get(User, closed_by_id):
            return jsonify(error='Choose who closed the school'), 400
        try:
            closed_on = parse_day(data.get('closed_on'), 'Close date')
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        splits = data.get('splits') or []
        if not isinstance(splits, list) or len(splits) > 10:
            return jsonify(error='Splits must be a list of up to 10 reps'), 400
        parsed, seen, total = [], set(), Decimal(0)
        for item in splits:
            if not isinstance(item, dict) or type(item.get('user_id')) is not int:
                return jsonify(error='Each split needs a rep'), 400
            if item['user_id'] in seen or not db.session.get(User, item['user_id']):
                return jsonify(error='Each split needs a different, existing rep'), 400
            try:
                share = percent(item.get('share_pct'), 'Share')
                rate = percent(item.get('rate_pct'), 'Rate')
            except ValueError as exc:
                return jsonify(error=str(exc)), 400
            if share is None or share <= 0:
                return jsonify(error='Each share must be more than 0%'), 400
            seen.add(item['user_id'])
            total += share
            parsed.append((item['user_id'], share, rate))
        if parsed and total != Decimal(100):
            return jsonify(error='Shares must add up to 100%'), 400

        was = school.status
        set_school_status(school, status, closed_by_id)
        school.closed_by_id = closed_by_id
        if closed_on:
            school.closed_at = closed_on + timedelta(hours=12)
        school.deal_value = deal_value.quantize(CENT) if deal_value is not None else None
        Split.query.filter_by(sales_school_id=school.id).delete()
        for user_id, share, rate in parsed:
            db.session.add(Split(sales_school_id=school.id, user_id=user_id, share_pct=share, rate_pct=rate))
        detail = 'Close recorded by an administrator' if was in CLOSED_STAGES else f'Closed by an administrator (was {was or "pending"})'
        db.session.add(Activity(sales_school_id=school.id, actor_id=admin.id, kind='close', detail=detail))
        db.session.commit()
        db.session.refresh(school)
        reps = {rep.id: rep for rep in User.query.all()}
        rows = Split.query.filter_by(sales_school_id=school.id).order_by(Split.id).all()
        return jsonify(close_dict(school, {school.id: rows} if rows else {}, reps))

    def link_dict(link):
        now = naive_utc()
        state = 'active'
        if link.revoked_at:
            state = 'revoked'
        elif link.expires_at <= now:
            state = 'expired'
        elif link.max_uses is not None and link.use_count >= link.max_uses:
            state = 'used up'
        return {'id': link.id, 'label': link.label, 'expires_at': link.expires_at.isoformat() + 'Z',
                'max_uses': link.max_uses, 'use_count': link.use_count, 'state': state,
                'created_at': link.created_at.isoformat() + 'Z'}

    @app.get('/api/join-links')
    @jwt_required()
    def list_join_links():
        if not current_admin():
            return forbidden()
        links = JoinLink.query.order_by(JoinLink.created_at.desc(), JoinLink.id.desc()).limit(20).all()
        return jsonify([link_dict(link) for link in links])

    @app.post('/api/join-links')
    @jwt_required()
    def create_join_link():
        admin = current_admin()
        if not admin:
            return forbidden()
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(error='Invalid request'), 400
        days = data.get('days', 7)
        max_uses = data.get('max_uses', 25)
        label = data.get('label')
        if days not in JOIN_LINK_DAYS:
            return jsonify(error='Choose 1, 7, 14 or 30 days'), 400
        if max_uses is not None and (type(max_uses) is not int or not 1 <= max_uses <= 200):
            return jsonify(error='Uses must be between 1 and 200'), 400
        if label is not None and (not isinstance(label, str) or len(label.strip()) > 80):
            return jsonify(error='Keep the label under 80 characters'), 400
        token = secrets.token_urlsafe(32)
        link = JoinLink(token_hash=hash_token(token), label=(label or '').strip() or None,
                        created_by=admin.id, expires_at=naive_utc() + timedelta(days=days), max_uses=max_uses)
        db.session.add(link)
        db.session.commit()
        return jsonify(token=token, **link_dict(link)), 201

    @app.delete('/api/join-links/<int:link_id>')
    @jwt_required()
    def revoke_join_link(link_id):
        if not current_admin():
            return forbidden()
        link = JoinLink.query.filter_by(id=link_id).with_for_update().first()
        if not link:
            return jsonify(error='Link not found'), 404
        if not link.revoked_at:
            link.revoked_at = naive_utc()
            db.session.commit()
        return jsonify(link_dict(link))

    @app.post('/api/join-links/check')
    def check_join_link():
        """Public: lets the sign-up page say whether a shared link still works."""
        data = request.get_json(silent=True)
        token = data.get('token') if isinstance(data, dict) else None
        return jsonify(valid=usable_join_link(JoinLink, token) is not None)
