"""Seasonal program commissions, separate from legacy school-close estimates.

Policy source: Christopher's email, 2026-10-28. Rep payout is explicit: the
email defines the pool but does not prescribe individual rep payout rates.
All arithmetic uses decimal cents and ROUND_HALF_UP, never binary floats.
"""
import csv
import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from io import StringIO

from flask import Response, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy.exc import IntegrityError

CENT = Decimal('0.01')
RATES = {'new': Decimal('15'), 'renewal': Decimal('7.5')}
FEE_RATE = Decimal('3.5')
LIMIT = Decimal('10000000000')


def cents(value):
    return value.quantize(CENT, rounding=ROUND_HALF_UP)


def amount(value, field):
    if isinstance(value, bool) or value is None or value == '':
        raise ValueError(f'{field} is required and must be a nonnegative dollar amount')
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f'{field} must be a dollar amount')
    if not result.is_finite() or result < 0 or result >= LIMIT:
        raise ValueError(f'{field} must be between 0 and 9,999,999,999.99')
    if result != cents(result):
        raise ValueError(f'{field} must have at most two decimal places')
    return result


def calculate(gross, leagueapps, expenses, sale_type, payout):
    if not isinstance(sale_type, str) or sale_type not in RATES:
        raise ValueError('Choose New or Renewal')
    if type(leagueapps) is not bool:
        raise ValueError('LeagueApps must be true or false')
    gross = amount(gross, 'Gross')
    expenses = amount(expenses, 'Cash expenses')
    fee = cents(gross * FEE_RATE / 100) if leagueapps else Decimal('0.00')
    net = gross - fee
    if expenses > net:
        raise ValueError('Cash expenses cannot exceed net revenue after the LeagueApps fee')
    base = net - expenses
    pool = cents(base * RATES[sale_type] / 100)
    payout = None if payout is None else amount(payout, 'Rep payout')
    if payout is not None and payout > pool:
        raise ValueError('Rep payout cannot exceed the commission pool')
    return dict(gross=gross, leagueapps_fee=fee, net=net, cash_expenses=expenses,
                commission_base=base, pool_rate=RATES[sale_type], pool=pool,
                rep_payout=payout, director_remainder=None if payout is None else pool - payout)


def register_program_commissions(app, db, User, School):
    class ProgramCommission(db.Model):
        __tablename__ = 'program_commissions'
        id = db.Column(db.Integer, primary_key=True)
        sales_school_id = db.Column(db.Integer, db.ForeignKey('sales_schools.id', ondelete='SET NULL'))
        school_name = db.Column(db.String(250), nullable=False)
        season = db.Column(db.String(80), nullable=False)
        program = db.Column(db.String(120), nullable=False)
        record_key = db.Column(db.String(240), nullable=False)
        rep_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
        rep_name = db.Column(db.String(250), nullable=False)
        sale_type = db.Column(db.String(10), nullable=False)
        gross = db.Column(db.Numeric(12, 2), nullable=False)
        leagueapps = db.Column(db.Boolean, nullable=False)
        cash_expenses = db.Column(db.Numeric(12, 2), nullable=False)
        rep_payout = db.Column(db.Numeric(12, 2))
        notes = db.Column(db.Text, nullable=False, default='')
        voided = db.Column(db.Boolean, nullable=False, default=False)
        revision = db.Column(db.Integer, nullable=False, default=1)
        updated_at = db.Column(db.DateTime, nullable=False)
        __table_args__ = (db.UniqueConstraint('sales_school_id', 'record_key', name='uq_program_commission'),)

    class ProgramCommissionEvent(db.Model):
        __tablename__ = 'program_commission_events'
        id = db.Column(db.Integer, primary_key=True)
        program_commission_id = db.Column(db.Integer, db.ForeignKey('program_commissions.id'), nullable=False)
        actor_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
        created_at = db.Column(db.DateTime, nullable=False)
        before_json = db.Column(db.Text)
        after_json = db.Column(db.Text, nullable=False)

    def admin():
        user = db.session.get(User, int(get_jwt_identity()))
        return user if user and user.admin else None

    def serialize(row):
        values = calculate(row.gross, row.leagueapps, row.cash_expenses, row.sale_type, row.rep_payout)
        return dict(id=row.id, sales_school_id=row.sales_school_id, school_name=row.school_name,
                    season=row.season, program=row.program, rep_id=row.rep_id, rep_name=row.rep_name,
                    sale_type=row.sale_type, leagueapps=row.leagueapps, notes=row.notes,
                    voided=row.voided, revision=row.revision, needs_review=row.rep_payout is None,
                    updated_at=row.updated_at.isoformat() + 'Z',
                    **{key: float(value) if value is not None else None for key, value in values.items()})

    def totals(rows):
        active = [row for row in rows if not row['voided']]
        keys = ('gross', 'leagueapps_fee', 'cash_expenses', 'commission_base', 'pool', 'rep_payout', 'director_remainder')
        result = {key: float(sum((Decimal(str(row[key])) for row in active if row[key] is not None), Decimal(0))) for key in keys}
        result.update(programs=len(active), needs_review=sum(row['needs_review'] for row in active),
                      unallocated_pool=float(sum((Decimal(str(row['pool'])) for row in active if row['needs_review']), Decimal(0))))
        return result

    @app.get('/api/admin/program-commissions')
    @jwt_required()
    def list_program_commissions():
        if not admin():
            return jsonify(error='Administrator access required'), 403
        query = ProgramCommission.query
        if request.args.get('season'):
            query = query.filter_by(season=request.args['season'])
        if request.args.get('rep_id'):
            try:
                rep_id = int(request.args['rep_id'])
            except ValueError:
                return jsonify(error='Invalid rep'), 400
            query = query.filter_by(rep_id=rep_id)
        rows = [serialize(row) for row in query.order_by(ProgramCommission.season.desc(), ProgramCommission.id.desc()).all()]
        if request.args.get('format') == 'csv':
            out = StringIO()
            fields = ['school_name', 'season', 'program', 'rep_name', 'sale_type', 'gross', 'leagueapps_fee',
                      'net', 'cash_expenses', 'commission_base', 'pool_rate', 'pool', 'rep_payout',
                      'director_remainder', 'needs_review', 'voided']
            writer = csv.writer(out)
            writer.writerow(fields)
            for row in rows:
                # Prevent a school/program name from becoming a spreadsheet formula.
                writer.writerow([("'" + str(row[key])) if isinstance(row[key], str) and row[key].startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else row[key] for key in fields])
            return Response(out.getvalue(), mimetype='text/csv', headers={
                'Content-Disposition': 'attachment; filename="psa-seasonal-commissions.csv"'})
        by_rep, by_season = {}, {}
        for row in rows:
            by_rep.setdefault(row['rep_id'] if row['rep_id'] is not None else ('former', row['rep_name']), []).append(row)
            by_season.setdefault(row['season'], []).append(row)
        return jsonify(records=rows, summary=totals(rows),
                       by_rep=[dict(rep_id=group[0]['rep_id'], rep_name=group[0]['rep_name'], **totals(group)) for group in by_rep.values()],
                       by_season=[dict(season=key, **totals(group)) for key, group in by_season.items()],
                       seasons=[r[0] for r in db.session.query(ProgramCommission.season).distinct().order_by(ProgramCommission.season.desc()).all()],
                       reps=[dict(id=r.id, name=r.name) for r in User.query.order_by(User.name).all()])

    @app.post('/api/admin/program-commissions')
    @app.put('/api/admin/program-commissions/<int:record_id>')
    @jwt_required()
    def save_program_commission(record_id=None):
        actor = admin()
        if not actor:
            return jsonify(error='Administrator access required'), 403
        row = ProgramCommission.query.filter_by(id=record_id).with_for_update().first() if record_id else None
        if record_id and not row:
            return jsonify(error='Program record not found'), 404
        data = request.get_json(silent=True)
        allowed = {'sales_school_id', 'season', 'program', 'rep_id', 'sale_type', 'gross', 'leagueapps',
                   'cash_expenses', 'rep_payout', 'notes', 'revision', 'voided'}
        if not isinstance(data, dict) or set(data) - allowed:
            return jsonify(error='Supply program commission fields only'), 400
        if row and (type(data.get('revision')) is not int or data['revision'] != row.revision):
            return jsonify(error='This record changed. Refresh before saving.'), 409
        before = serialize(row) if row else None
        try:
            for field, maximum in (('season', 80), ('program', 120)):
                if not isinstance(data.get(field), str) or not 1 <= len(data[field].strip()) <= maximum:
                    raise ValueError(f'{field.title()} is required (up to {maximum} characters)')
            if type(data.get('rep_id')) is not int or not (rep := db.session.get(User, data['rep_id'])):
                raise ValueError('Choose an existing sales rep')
            if row and data.get('sales_school_id') != row.sales_school_id:
                raise ValueError('The school cannot be changed on an existing program record')
            school = None
            if not row:
                if type(data.get('sales_school_id')) is not int or not (school := db.session.get(School, data['sales_school_id'])):
                    raise ValueError('Choose an existing school')
            values = calculate(data.get('gross'), data.get('leagueapps'), data.get('cash_expenses'), data.get('sale_type'), data.get('rep_payout'))
            notes = data.get('notes', '')
            if not isinstance(notes, str) or len(notes) > 4000:
                raise ValueError('Notes must be text up to 4,000 characters')
            if type(data.get('voided', False)) is not bool:
                raise ValueError('Voided must be true or false')
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        season = ' '.join(data['season'].split())
        existing_seasons = db.session.query(ProgramCommission.season).distinct().all()
        if not row:
            row = ProgramCommission(sales_school_id=school.id, school_name=school.school_name[:250], revision=0)
            db.session.add(row)
        row.season = next((value for (value,) in existing_seasons if value.casefold() == season.casefold()), season)
        row.program = ' '.join(data['program'].split())
        row.record_key = ' '.join(row.season.casefold().split()) + '\x1f' + ' '.join(row.program.casefold().split())
        row.rep_id, row.rep_name = rep.id, rep.name[:250]
        row.sale_type, row.leagueapps = data['sale_type'], data['leagueapps']
        row.gross, row.cash_expenses, row.rep_payout = values['gross'], values['cash_expenses'], values['rep_payout']
        row.notes, row.voided = notes.strip(), data.get('voided', False)
        row.revision += 1
        row.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        try:
            db.session.flush()
            after = serialize(row)
            db.session.add(ProgramCommissionEvent(program_commission_id=row.id, actor_id=actor.id,
                created_at=row.updated_at, before_json=json.dumps(before) if before else None, after_json=json.dumps(after)))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify(error='This school already has a record for that season and program. Edit it instead.'), 409
        return jsonify(after), 200 if record_id else 201

    @app.get('/api/admin/program-commissions/<int:record_id>/history')
    @jwt_required()
    def program_commission_history(record_id):
        if not admin():
            return jsonify(error='Administrator access required'), 403
        if not db.session.get(ProgramCommission, record_id):
            return jsonify(error='Program record not found'), 404
        events = ProgramCommissionEvent.query.filter_by(program_commission_id=record_id).order_by(ProgramCommissionEvent.id).all()
        return jsonify([dict(id=e.id, actor_id=e.actor_id, created_at=e.created_at.isoformat() + 'Z',
                             before=json.loads(e.before_json) if e.before_json else None, after=json.loads(e.after_json)) for e in events])

    return ProgramCommission, ProgramCommissionEvent
