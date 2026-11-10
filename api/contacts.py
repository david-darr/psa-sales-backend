"""Contact identities, school associations and reviewed CSV import.

Mailbox identity is shared; role/name/tags belong to a school association.
Legacy email fields remain the sending projection in this release.
"""
import csv
import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from io import StringIO

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import event, inspect, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import object_session

ROLES = ('unknown', 'principal_ap', 'pta_pto', 'enrichment', 'other_staff')
STAGES = ('pending', 'contacted', 'replied', 'meeting', 'partner', 'former', 'not_interested')
ALIASES = {'principal': 'principal_ap', 'ap': 'principal_ap', 'principal/ap': 'principal_ap',
           'pta': 'pta_pto', 'pto': 'pta_pto', 'pta officer': 'pta_pto',
           'enrichment coordinator': 'enrichment', 'asep': 'enrichment', 'other': 'other_staff'}


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalized(value):
    return ' '.join((value or '').strip().casefold().split())


def mailbox(value):
    if not isinstance(value, str) or len(value) > 254 or not re.fullmatch(r'[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+', value.strip()):
        raise ValueError('Enter one valid email address per contact row')
    return value.strip().casefold()


def text(value, maximum, field):
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f'{field} must be text up to {maximum} characters')
    return value.strip()


def roles(value):
    if value is not None and not isinstance(value, (str, list)):
        raise ValueError('Invalid contact roles')
    parts = value if isinstance(value, list) else re.split(r'[;|]', value or 'unknown')
    if not isinstance(parts, list) or any(not isinstance(item, str) for item in parts):
        raise ValueError('Invalid contact roles')
    result = sorted(set(ALIASES.get(normalized(item), normalized(item)) for item in parts))
    if not result or any(item not in ROLES for item in result):
        raise ValueError('Roles: ' + ', '.join(ROLES))
    return [item for item in result if item != 'unknown'] or ['unknown']


def school_matches(name, address, county, candidates):
    """Email is NOT school identity: PTAs can share a mailbox across schools."""
    n, a, c = normalized(name), normalized(address), normalized(county)
    exact, possible = [], []
    base = lambda value: re.sub(r'\s*\([^)]*\)', '', normalized(value))
    for school in candidates:
        sn, sa, sc = normalized(school.school_name), normalized(school.address), normalized(school.county)
        if c and sc and c != sc:
            continue
        if n == sn and a == sa:
            exact.append(school)
        elif ((n == sn and (not a or not sa)) or
              (a and a == sa) or
              base(n) == base(sn) or
              SequenceMatcher(None, n, sn).ratio() >= .86):
            possible.append(school)
    return exact, possible


def register_contacts(app, db, User, School, Activity):
    class Contact(db.Model):
        __tablename__ = 'contacts'
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(254), nullable=False, unique=True)
        do_not_contact = db.Column(db.Boolean, nullable=False, default=False, server_default='false')
        suppression_reason = db.Column(db.Text, nullable=False, default='', server_default='')
        version = db.Column(db.Integer, nullable=False, default=1, server_default='1')

    class SchoolContact(db.Model):
        __tablename__ = 'school_contacts'
        id = db.Column(db.Integer, primary_key=True)
        school_id = db.Column(db.Integer, db.ForeignKey('sales_schools.id', ondelete='CASCADE'), nullable=False)
        contact_id = db.Column(db.Integer, db.ForeignKey('contacts.id'), nullable=False, index=True)
        name = db.Column(db.String(150), nullable=False, default='', server_default='')
        roles_json = db.Column(db.Text, nullable=False, default='["unknown"]', server_default='["unknown"]')
        tags_json = db.Column(db.Text, nullable=False, default='[]', server_default='[]')
        is_primary = db.Column(db.Boolean, nullable=False, default=False, server_default='false')
        version = db.Column(db.Integer, nullable=False, default=1, server_default='1')
        __table_args__ = (db.UniqueConstraint('school_id', 'contact_id', name='uq_school_contact'),)

    class ContactEvent(db.Model):
        __tablename__ = 'contact_events'
        id = db.Column(db.Integer, primary_key=True)
        contact_id = db.Column(db.Integer, db.ForeignKey('contacts.id'), nullable=False)
        school_id = db.Column(db.Integer, db.ForeignKey('sales_schools.id', ondelete='SET NULL'))
        actor_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
        created_at = db.Column(db.DateTime, nullable=False, default=now)
        detail = db.Column(db.Text, nullable=False)

    class ContactImport(db.Model):
        __tablename__ = 'contact_imports'
        id = db.Column(db.String(64), primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
        file_hash = db.Column(db.String(64), nullable=False)
        rows_json = db.Column(db.Text, nullable=False)
        plan_json = db.Column(db.Text, nullable=False)
        snapshot = db.Column(db.String(64), nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False)
        result_json = db.Column(db.Text)

    class ContactImportGuard(db.Model):
        __tablename__ = 'contact_import_guard'
        id = db.Column(db.Integer, primary_key=True)
        revision = db.Column(db.Integer, nullable=False)

    def insert(connection, table, values, keys):
        factory = pg_insert if connection.dialect.name == 'postgresql' else sqlite_insert
        connection.execute(factory(table).values(**values).on_conflict_do_nothing(index_elements=keys))

    def lock_writes():
        connection = db.session.connection()
        insert(connection, ContactImportGuard.__table__, {'id': 1, 'revision': 0}, ['id'])
        connection.execute(update(ContactImportGuard).where(ContactImportGuard.id == 1).values(revision=ContactImportGuard.revision + 1))

    def sync_legacy(_mapper, connection, school):
        """All legacy ORM writes materialize contacts in their own transaction."""
        state = inspect(school)
        if object_session(school).info.get('contact_import_owned'):
            return  # reviewed imports write canonical rows and their projection together
        if state.persistent and not any(state.attrs[key].history.has_changes() for key in ('email', 'additional_emails', 'contact_name')):
            return
        addresses = []
        for value in school.get_all_emails():
            try:
                address = mailbox(value)
            except ValueError:
                continue  # old malformed data stays visible in the old field, never guessed
            if address not in addresses:
                addresses.append(address)
        links = SchoolContact.__table__
        wanted_ids = select(Contact.id).where(Contact.email.in_(addresses))
        connection.execute(links.delete().where(links.c.school_id == school.id, links.c.contact_id.not_in(wanted_ids)))
        connection.execute(update(links).where(links.c.school_id == school.id).values(is_primary=False))
        for address in addresses:
            insert(connection, Contact.__table__, {'email': address}, ['email'])
            cid = connection.execute(select(Contact.id).where(Contact.email == address)).scalar_one()
            primary = address == normalized(school.email)
            insert(connection, links, {'school_id': school.id, 'contact_id': cid,
                'name': (school.contact_name or '')[:150] if primary else '', 'is_primary': primary}, ['school_id', 'contact_id'])
            connection.execute(update(links).where(links.c.school_id == school.id, links.c.contact_id == cid).values(is_primary=primary))
            if primary and state.attrs.contact_name.history.has_changes():
                connection.execute(update(links).where(links.c.school_id == school.id, links.c.contact_id == cid).values(name=(school.contact_name or '')[:150], version=links.c.version + 1))

    event.listen(School, 'after_insert', sync_legacy)
    event.listen(School, 'after_update', sync_legacy)

    def current():
        return db.session.get(User, int(get_jwt_identity()))

    def accessible(sid, user, lock=False):
        school = School.query.filter_by(id=sid).populate_existing().with_for_update().first() if lock else db.session.get(School, sid)
        return school if school and user and (user.admin or school.user_id == user.id) else None

    def blocked(address, independent=False):
        if independent and db.engine.dialect.name == 'postgresql':
            with db.engine.connect() as connection:
                return connection.execute(select(Contact.id).where(Contact.email == normalized(address), Contact.do_not_contact.is_(True))).first() is not None
        return Contact.query.filter_by(email=normalized(address), do_not_contact=True).first() is not None

    def serialize(link, user):
        contact = db.session.get(Contact, link.contact_id)
        linked = School.query.join(SchoolContact, SchoolContact.school_id == School.id).filter(SchoolContact.contact_id == contact.id).all()
        visible = [s for s in linked if user.admin or s.user_id == user.id]
        return dict(id=link.id, contact_id=contact.id, email=contact.email, name=link.name,
                    roles=json.loads(link.roles_json), tags=json.loads(link.tags_json), is_primary=link.is_primary,
                    version=link.version, contact_version=contact.version, do_not_contact=contact.do_not_contact,
                    suppression_reason=contact.suppression_reason,
                    shared_schools=[dict(id=s.id, name=s.school_name) for s in visible], linked_school_count=len(linked))

    def audit(contact, school, user, detail):
        db.session.add(ContactEvent(contact_id=contact.id, school_id=school.id, actor_id=user.id, detail=detail))

    def project(school):
        """Contacts own new writes; preserve the primary chosen by the employee."""
        db.session.flush()
        links = SchoolContact.query.filter_by(school_id=school.id).order_by(SchoolContact.is_primary.desc(), SchoolContact.id).all()
        if not links:
            return
        primary = links[0]
        if not primary.is_primary:
            primary.is_primary = True
        school.email = db.session.get(Contact, primary.contact_id).email
        school.contact_name = primary.name or None
        school.set_additional_emails([db.session.get(Contact, link.contact_id).email for link in links[1:]])

    @app.route('/api/sales-schools/<int:sid>/contacts', methods=['GET', 'POST'])
    @jwt_required()
    def school_contacts(sid):
        user = current()
        school = accessible(sid, user)
        if not school:
            return jsonify(error='School not found'), 404
        if request.method == 'GET':
            links = SchoolContact.query.filter_by(school_id=sid).order_by(SchoolContact.is_primary.desc(), SchoolContact.id).all()
            return jsonify(contacts=[serialize(link, user) for link in links], roles=list(ROLES), county=school.county or '')
        data = request.get_json(silent=True)
        try:
            if not isinstance(data, dict) or set(data) - {'email', 'name', 'roles', 'tags', 'is_primary', 'do_not_contact', 'suppression_reason'}:
                raise ValueError('Supply contact fields only')
            address = mailbox(data.get('email'))
            name = text(data.get('name', ''), 150, 'Name')
            wanted_roles = roles(data.get('roles'))
            tags = parse_tags(data.get('tags', []))
            if type(data.get('is_primary', False)) is not bool:
                raise ValueError('Primary must be true or false')
            dnc = data.get('do_not_contact', False)
            reason = text(data.get('suppression_reason', ''), 500, 'Suppression reason')
            if type(dnc) is not bool or (dnc and not reason):
                raise ValueError('Record a reason for do-not-contact')
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        lock_writes()
        school = accessible(sid, user, lock=True)
        if not school:
            return jsonify(error='School not found'), 404
        contact = Contact.query.filter_by(email=address).first()
        if not contact:
            contact = Contact(email=address)
            db.session.add(contact); db.session.flush()
        if SchoolContact.query.filter_by(school_id=sid, contact_id=contact.id).first():
            return jsonify(error='This email is already linked to this school. Edit its contact instead.'), 409
        if dnc and not contact.do_not_contact:
            contact.do_not_contact, contact.suppression_reason = True, reason
            contact.version += 1
        link = SchoolContact(school_id=sid, contact_id=contact.id, name=name,
                             roles_json=json.dumps(wanted_roles), tags_json=json.dumps(tags))
        if data.get('is_primary'):
            SchoolContact.query.filter_by(school_id=sid).update({'is_primary': False})
            link.is_primary = True
        db.session.add(link); db.session.flush()
        project(school)
        audit(contact, school, user, 'Contact linked to school')
        db.session.commit()
        return jsonify(serialize(link, user)), 201

    @app.patch('/api/sales-schools/<int:sid>/contacts/<int:lid>')
    @jwt_required()
    def patch_contact(sid, lid):
        user = current()
        school = accessible(sid, user)
        if not school:
            return jsonify(error='School not found'), 404
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) - {'name', 'roles', 'tags', 'is_primary', 'do_not_contact', 'suppression_reason', 'version', 'contact_version'}:
            return jsonify(error='Supply contact changes only'), 400
        lock_writes()
        school = accessible(sid, user, lock=True)
        if not school:
            return jsonify(error='School not found'), 404
        link = SchoolContact.query.filter_by(id=lid, school_id=sid).first()
        if not link:
            return jsonify(error='Contact not found'), 404
        contact = db.session.get(Contact, link.contact_id)
        if (type(data.get('version')) is not int or data['version'] != link.version or
                type(data.get('contact_version')) is not int or data['contact_version'] != contact.version):
            return jsonify(error='This contact changed. Refresh before saving.'), 409
        try:
            name = text(data.get('name', link.name), 150, 'Name')
            wanted_roles = roles(data.get('roles', json.loads(link.roles_json)))
            tags = parse_tags(data.get('tags', json.loads(link.tags_json)))
            if 'is_primary' in data and data['is_primary'] is not True:
                raise ValueError('Choose another primary contact instead of clearing this one')
            dnc = data.get('do_not_contact', contact.do_not_contact)
            if type(dnc) is not bool:
                raise ValueError('Do not contact must be true or false')
            if contact.do_not_contact and not dnc and not user.admin:
                return jsonify(error='Only an administrator can clear do-not-contact'), 403
            reason = text(data.get('suppression_reason', contact.suppression_reason), 500, 'Suppression reason')
            if dnc != contact.do_not_contact and not reason:
                raise ValueError('Record a reason when changing do-not-contact')
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        before = serialize(link, user)
        link.name, link.roles_json, link.tags_json = name, json.dumps(wanted_roles), json.dumps(tags)
        link.version += 1
        if data.get('is_primary'):
            SchoolContact.query.filter_by(school_id=sid).update({'is_primary': False})
            link.is_primary = True
        contact.do_not_contact, contact.suppression_reason = dnc, reason
        contact.version += 1
        project(school)
        audit(contact, school, user, json.dumps({'before': before, 'after': serialize(link, user)}))
        db.session.commit()
        return jsonify(serialize(link, user))

    def snapshot():
        values = [
            [(s.id, s.school_name, s.address, s.county, s.user_id, s.status, s.email, s.additional_emails, s.notes) for s in School.query.order_by(School.id)],
            [(c.id, c.email, c.version, c.do_not_contact) for c in Contact.query.order_by(Contact.id)],
            [(l.id, l.school_id, l.contact_id, l.version, l.name, l.roles_json, l.tags_json, l.is_primary) for l in SchoolContact.query.order_by(SchoolContact.id)],
        ]
        return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()

    def build_plan(rows, user):
        schools = School.query.order_by(School.id).all()
        existing_contacts = {contact.email: contact for contact in Contact.query.all()}
        existing_links = {(link.school_id, link.contact_id) for link in SchoolContact.query.all()}
        groups, errors = {}, []
        for number, raw in enumerate(rows, 2):
            try:
                row = parse_row(raw)
                key = hashlib.sha256(json.dumps([normalized(row[k]) for k in ('school_name', 'address', 'county')]).encode()).hexdigest()[:24]
                if key not in groups:
                    exact, possible = school_matches(row['school_name'], row['address'], row['county'], schools)
                    hits = exact or possible
                    target = exact[0] if len(exact) == 1 else None
                    if target and not (user.admin or target.user_id == user.id):
                        target = None
                    groups[key] = dict(key=key, school_name=row['school_name'], address=row['address'], county=row['county'],
                        action='existing' if target else 'conflict' if hits else 'new',
                        school_id=target.id if target else None,
                        candidates=[dict(id=s.id if user.admin or s.user_id == user.id else None,
                            name=s.school_name, address=s.address or '', editable=user.admin or s.user_id == user.id) for s in hits[:8]],
                        rows=[], warnings=[])
                    for other_key, other in groups.items():
                        if other_key != key and (re.sub(r'\s*\([^)]*\)', '', normalized(other['school_name'])) == re.sub(r'\s*\([^)]*\)', '', normalized(row['school_name'])) or
                                SequenceMatcher(None, normalized(other['school_name']), normalized(row['school_name'])).ratio() >= .86):
                            groups[key]['action'] = 'conflict'
                            groups[key]['warnings'].append('Possible duplicate within this CSV. Correct/group the rows, skip it, or explicitly create a separate school.')
                group = groups[key]
                if group['rows']:
                    first = group['rows'][0]
                    for field in ('school_type', 'stage', 'notes'):
                        if first[field] and row[field] and first[field] != row[field]:
                            raise ValueError(f'Conflicting {field} for this school; correct the CSV')
                        if not first[field] and row[field]:
                            first[field] = row[field]
                existing_contact = existing_contacts.get(row['email'])
                if existing_contact:
                    group['warnings'] = sorted(set(group['warnings'] + ['Existing mailbox: may be shared or suppressed. Suppression is preserved.']))
                target_link = existing_contact and (group['school_id'], existing_contact.id) in existing_links
                contact_action = 'existing_contact' if target_link else 'shared_contact' if existing_contact else 'add_contact'
                if any(previous['email'] == row['email'] for previous in group['rows']):
                    contact_action = 'duplicate_row'
                group['rows'].append(dict(row, row_number=number, contact_action=contact_action,
                    existing_do_not_contact=bool(existing_contact and existing_contact.do_not_contact)))
            except ValueError as exc:
                errors.append(dict(row_number=number, message=str(exc)))
        return dict(groups=list(groups.values()), errors=errors, row_count=len(rows))

    @app.post('/api/contact-imports/preview')
    @jwt_required()
    def preview_import():
        user = current()
        if not user:
            return jsonify(error='User not found'), 404
        supported = {'school_name', 'email', 'contact_name', 'contact_role', 'address', 'county',
                     'school_type', 'stage', 'notes', 'phone', 'audience_tags', 'do_not_contact', 'suppression_reason'}
        data=request.get_json(silent=True) if request.is_json else None
        if request.is_json:
            if not isinstance(data,dict) or set(data)!={'rows'} or not isinstance(data['rows'],list) or not 1<=len(data['rows'])<=2000:
                return jsonify(error='Supply 1 to 2,000 school/contact rows'),400
            rows=data['rows']
            if any(not isinstance(r,dict) or set(r)-supported or any(not isinstance(v,str) for v in r.values()) for r in rows):
                return jsonify(error='Use supported import columns with text values only'),400
            raw=json.dumps(rows,sort_keys=True,separators=(',',':')).encode()
        else:
            upload = request.files.get('file')
            if not upload or not (upload.filename or '').lower().endswith('.csv'):
                return jsonify(error='Choose a CSV file'), 400
            raw = upload.read(2_000_001)
        if len(raw) > 2_000_000:
            return jsonify(error='CSV limit is 2 MB'), 400
        try:
            reader = csv.DictReader(StringIO(raw.decode('utf-8-sig'))) if not request.is_json else None
            if request.is_json:
                plan=build_plan(rows,user)
            else:
                plan=None
            if reader is not None:
                rows, headers = [], [column_name(h) for h in (reader.fieldnames or [])]
                if not headers or len(headers)!=len(set(headers)) or not {'school_name','email'}.issubset(headers):
                    raise ValueError('Use unique headers including school_name and email')
                if set(headers)-supported: raise ValueError('Unrecognized CSV columns: '+', '.join(sorted(set(headers)-supported)))
                for record in reader:
                    if len(rows)>=2000: raise ValueError('Preview up to 2,000 rows at a time')
                    if None in record or any(value is None for value in record.values()): raise ValueError('A CSV row has the wrong number of columns')
                    rows.append({column_name(k):v for k,v in record.items()})
                if not rows: raise ValueError('The CSV is empty')
                plan=build_plan(rows,user)
        except (ValueError, UnicodeError, csv.Error) as exc:
            return jsonify(error=str(exc)), 400
        preview = ContactImport(id=secrets.token_urlsafe(24), user_id=user.id,
            file_hash=hashlib.sha256(raw).hexdigest(), rows_json=json.dumps(rows), plan_json=json.dumps(plan),
            snapshot=snapshot(), expires_at=now() + timedelta(minutes=30))
        db.session.add(preview); db.session.commit()
        return jsonify(id=preview.id, file_hash=preview.file_hash, expires_at=preview.expires_at.isoformat() + 'Z', **plan)

    @app.post('/api/contact-imports/<string:pid>/commit')
    @jwt_required()
    def commit_import(pid):
        user = current()
        if not user:
            return jsonify(error='User not found'), 404
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) - {'file_hash', 'decisions', 'skip_invalid'}:
            return jsonify(error='Supply the reviewed import and decisions'), 400
        lock_writes()
        preview = ContactImport.query.filter_by(id=pid, user_id=user.id).first()
        if not preview:
            return jsonify(error='Import preview not found'), 404
        if data.get('file_hash') != preview.file_hash:
            return jsonify(error='The reviewed file does not match'), 409
        if preview.result_json:
            return jsonify(json.loads(preview.result_json))
        if now() > preview.expires_at or snapshot() != preview.snapshot:
            return jsonify(error='The preview expired or school/contact records changed. Preview the file again.'), 409
        plan = json.loads(preview.plan_json)
        decisions = data.get('decisions', {})
        if not isinstance(decisions, dict) or set(decisions) - {g['key'] for g in plan['groups']}:
            return jsonify(error='Invalid school decisions'), 400
        if plan['errors'] and data.get('skip_invalid') is not True:
            return jsonify(error='Review invalid rows and explicitly choose to skip them, or correct the CSV.'), 400
        targets = []
        for group in plan['groups']:
            choice = decisions.get(group['key'], {})
            if not isinstance(choice, dict) or set(choice) - {'action', 'school_id'}:
                return jsonify(error='Invalid school decision'), 400
            action = choice.get('action', group['action'])
            if action == 'skip':
                continue
            if action not in ('new', 'existing'):
                return jsonify(error='Resolve every possible school duplicate before importing'), 400
            if action == 'new' and group['action'] == 'existing':
                return jsonify(error='An exact school match already exists. Add contacts to it or skip it.'), 400
            sid = choice.get('school_id', group['school_id'])
            school = None
            if action == 'existing':
                if type(sid) is not int or not (school := accessible(sid, user, lock=True)):
                    return jsonify(error='A selected school is unavailable or belongs to another rep'), 403
                allowed_ids = {candidate['id'] for candidate in group['candidates']}
                if sid not in allowed_ids:
                    return jsonify(error='Choose a school from the reviewed matches'), 400
            targets.append((group, school))
        all_contacts = {contact.email: contact for contact in Contact.query.all()}
        all_links = {(link.school_id, link.contact_id): link for link in SchoolContact.query.all()}
        initial_links = set(all_links)
        linked_contacts = {link.contact_id for link in all_links.values()}
        result = dict(schools_added=0, schools_updated=0, contacts_added=0, shared_contacts=0,
                      duplicates=0, rows_skipped=len(plan['errors']), schools_skipped=len(plan['groups']) - len(targets))
        processed = set()
        db.session.info['contact_import_owned'] = True
        try:
            for address in {row['email'] for group, _ in targets for row in group['rows']} - all_contacts.keys():
                contact = Contact(email=address)
                all_contacts[address] = contact
                db.session.add(contact)
            db.session.flush()  # insert all new mailbox identities as one ORM batch
            by_id = {contact.id: contact for contact in all_contacts.values()}
            for group, school in targets:
                first = group['rows'][0]
                if school is None:
                    school = School(school_name=first['school_name'], address=first['address'], county=first['county'],
                        email=first['email'], contact_name=first['contact_name'], school_type=first['school_type'],
                        phone=first['phone'], status=first['stage'] or 'pending', notes=first['notes'], user_id=user.id)
                    db.session.add(school); db.session.flush()
                    result['schools_added'] += 1
                else:
                    result['schools_updated'] += 1
                    if not school.county and first['county']:
                        school.county = first['county']
                    # Existing owner, stage and notes are NEVER overwritten.
                for row in group['rows']:
                    contact = all_contacts[row['email']]
                    key = school.id, contact.id
                    link = all_links.get(key)
                    if link is None:
                        if contact.id in linked_contacts:
                            result['shared_contacts'] += 1
                        linked_contacts.add(contact.id)
                        link = SchoolContact(school_id=school.id, contact_id=contact.id, name=row['contact_name'],
                            roles_json=json.dumps(row['roles']), tags_json=json.dumps(row['tags']),
                            is_primary=normalized(school.email) == contact.email, version=1)
                        all_links[key] = link
                        db.session.add(link)
                    else:
                        if key in initial_links or key in processed:
                            result['duplicates'] += 1
                        if not link.name:
                            link.name = row['contact_name']
                        link.roles_json = json.dumps(roles(json.loads(link.roles_json) + row['roles']))
                        link.tags_json = json.dumps(sorted(set(json.loads(link.tags_json) + row['tags'])))
                        link.version += 1
                    if row['do_not_contact'] and not contact.do_not_contact:
                        contact.do_not_contact, contact.suppression_reason = True, row['suppression_reason'] or 'Imported do-not-contact'
                        contact.version += 1
                    processed.add(key)
                    audit(contact, school, user, f'CSV import {preview.file_hash[:12]} row {row["row_number"]}')
                school_links = [link for (sid, _), link in all_links.items() if sid == school.id]
                school_links.sort(key=lambda link: (not link.is_primary, link.id or 2**31))
                primary = school_links[0]
                primary.is_primary = True
                school.email = by_id[primary.contact_id].email
                school.contact_name = primary.name or None
                school.set_additional_emails([by_id[link.contact_id].email for link in school_links[1:]])
            db.session.flush()
        finally:
            db.session.info.pop('contact_import_owned', None)
        result['contacts_added'] = len(all_links) - len(initial_links)
        preview.result_json = json.dumps(result)
        db.session.commit()
        return jsonify(result)

    return Contact, SchoolContact, ContactEvent, ContactImport, blocked, lock_writes


def parse_tags(value):
    if isinstance(value, str):
        value = re.split(r'[;|]', value) if value.strip() else []
    if not isinstance(value, list) or len(value) > 20:
        raise ValueError('Use up to 20 audience tags')
    return sorted(set(text(item, 80, 'Tag') for item in value if item))


def column_name(value):
    key = (value or '').strip().casefold().replace(' ', '_').replace('-', '_')
    return {'name': 'school_name', 'school': 'school_name', 'schoolname': 'school_name', 'email_address': 'email', 'e_mail': 'email',
        'school_email': 'email', 'contact_email': 'email', 'contact': 'contact_name', 'director': 'contact_name',
        'principal': 'contact_name', 'contactname': 'contact_name', 'type': 'school_type', 'category': 'school_type', 'schooltype': 'school_type',
        'status': 'stage', 'school_address': 'address', 'location': 'address', 'addr': 'address',
        'phone_number': 'phone', 'telephone': 'phone', 'tel': 'phone', 'phonenumber': 'phone'}.get(key, key)


def parse_row(raw):
    name = text(raw.get('school_name', ''), 240, 'School name')
    if not name:
        raise ValueError('School name is required')
    kind = normalized(raw.get('school_type', '')) or 'preschool'
    kind = {'elementary school': 'elementary', 'public school': 'elementary', 'daycare': 'preschool', 'private school': 'private'}.get(kind, kind)
    stage = normalized(raw.get('stage', ''))
    if kind not in ('preschool', 'elementary', 'private') or (stage and stage not in STAGES):
        raise ValueError('Invalid school type or stage')
    dnc = normalized(raw.get('do_not_contact', ''))
    if dnc not in ('', 'true', 'false', 'yes', 'no', '1', '0'):
        raise ValueError('do_not_contact must be true or false')
    return dict(school_name=name, email=mailbox(raw.get('email')), school_type=kind, stage=stage,
        address=text(raw.get('address', ''), 500, 'Address'), county=text(raw.get('county', ''), 80, 'County'),
        contact_name=text(raw.get('contact_name', ''), 150, 'Contact name'), roles=roles(raw.get('contact_role')),
        phone=text(raw.get('phone', ''), 80, 'Phone'), notes=text(raw.get('notes', ''), 4000, 'Notes'),
        tags=parse_tags(raw.get('audience_tags', '')), do_not_contact=dnc in ('true', 'yes', '1'),
        suppression_reason=text(raw.get('suppression_reason', ''), 500, 'Suppression reason'))
