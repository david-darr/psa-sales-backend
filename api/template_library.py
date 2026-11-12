"""Shared, versioned outreach copy. Saving a template never schedules or sends mail."""
from .sales_workspaces import requested_area
import base64
import functools
import hashlib
import json
import re
import uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta
from flask import jsonify, request, send_file
from werkzeug.utils import secure_filename
import io
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

FIELDS = {'business name': 'business_name', 'school name': 'school_name', 'contact name': 'contact_name', 'my name': 'user_name', 'my email': 'user_email'}
ALIASES = {value: key for key, value in FIELDS.items()}
TOKEN = re.compile(r"\{([^{}]*)\}|\[([^\[\]\r\n]*)\]")
AUDIENCES = {'principal_ap', 'pta_pto', 'enrichment', 'trunk_or_treat', 'general', 'decision_maker', 'marketing', 'community_relations'}
APPROVED_PDFS = ('PSA TOTS seasonal flyer.pdf', 'PSA TOTS year round flyer.pdf',
                 'PSA TOTS Recommendation (Primrose School).pdf', 'PSA After School.pdf',
                 'PSA Recommendation (St. Theresa).pdf', 'PSA Recommendation Letter (Madison Trust ES).pdf')
MAX_PDF_BYTES = 10 * 1024 * 1024
MAX_TEMPLATE_BYTES = 15 * 1024 * 1024
MAX_ATTACHMENTS = 3
PDF_DIRECTORY = Path(__file__).parent / 'pdf_attachments'
SEED = Path(__file__).parent / 'seed_data' / 'winter_2027_templates.json'


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def validate_encoding(*values):
    # Detect specific UTF-8/Windows-1252 corruption, never silently rewrite copy.
    if any(re.search(r'\u00c2\u00b7|\u00e2\u20ac[\u2122\u0153\u201c\u201d\u2013\u2014\u00a6]|\ufffd', value) for value in values):
        raise ValueError('Text appears to contain damaged characters. Copy the original text or upload a UTF-8 JSON file, then review it again.')


def validate_copy(subject, body):
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 200 or any(c in subject for c in '\r\n'):
        raise ValueError('Enter a subject of 1 to 200 characters, without line breaks.')
    if not isinstance(body, str) or not body.strip() or len(body) > 20000:
        raise ValueError('Enter a message of 1 to 20,000 characters.')
    validate_encoding(subject,body)
    for match in TOKEN.finditer(subject + '\n' + body):
        key = match[1] if match[1] is not None else ALIASES.get(match[2])
        if key not in FIELDS:
            raise ValueError('Unsupported merge field: ' + match[0])
    # Catch unfinished/malformed curly merge fields as well.
    remaining = TOKEN.sub('', subject + '\n' + body)
    if '{' in remaining or '}' in remaining:
        raise ValueError('A merge field has unmatched braces.')


def render_copy(subject, body, school, user):
    validate_copy(subject, body)
    values = {'business name': school.school_name, 'school name': school.school_name, 'contact name': school.contact_name,
              'my name': user.name, 'my email': user.email}
    def replace(match):
        key = match[1] if match[1] is not None else ALIASES[match[2]]
        value = (values.get(key) or '').strip()
        if not value:
            raise ValueError('Missing ' + key + ' for ' + school.school_name + '.')
        return value
    result = TOKEN.sub(replace, subject), TOKEN.sub(replace, body)
    validate_encoding(*result)
    if len(result[0]) > 200 or any(c in result[0] for c in '\r\n'):
        raise ValueError('The merged subject must have at most 200 characters and no line breaks.')
    return result


def register_templates(app, db, User):
    class TemplateUploadRequest(app.request_class):
        @property
        def max_content_length(self):
            inherited = super().max_content_length
            if self.path == '/api/outreach/template-imports/preview' and self.method == 'POST':
                return min(inherited, 2 * 1024 * 1024) if inherited is not None else 2 * 1024 * 1024
            if self.path == '/api/outreach/template-assets' and self.method == 'POST':
                cap = MAX_PDF_BYTES + 1024 * 1024
                return min(inherited, cap) if inherited is not None else cap
            return inherited
    app.request_class = TemplateUploadRequest
    class TemplateAsset(db.Model):
        __tablename__ = 'mail_template_assets'
        id = db.Column(db.String(64), primary_key=True)
        name = db.Column(db.String(180), nullable=False)
        payload = db.Column(db.LargeBinary, nullable=False)
        created_at = db.Column(db.DateTime, nullable=False, default=now)

    @functools.lru_cache(maxsize=4)
    def attachment_payload(asset_id):
        # Do not hold a Postgres connection during SMTP. SQLite is used only by local tests.
        if db.engine.dialect.name == 'sqlite':
            asset = db.session.get(TemplateAsset, asset_id)
            result = (asset.name, asset.payload) if asset else None
        else:
            from sqlalchemy import select
            with db.engine.connect() as connection:
                result = connection.execute(select(TemplateAsset.name, TemplateAsset.payload).where(TemplateAsset.id == asset_id)).first()
        if not result or hashlib.sha256(result[1]).hexdigest() != asset_id:
            raise ValueError('The saved template attachment is unavailable or invalid. Nothing was sent.')
        return result[0], base64.encodebytes(result[1]).decode('ascii')

    class MailTemplate(db.Model):
        __tablename__ = 'mail_templates'
        id = db.Column(db.Integer, primary_key=True)
        source_key = db.Column(db.String(120), unique=True)
        revision = db.Column(db.Integer, nullable=False, default=1)
        archived = db.Column(db.Boolean, nullable=False, default=False)
        created_at = db.Column(db.DateTime, nullable=False, default=now)

    class MailTemplateVersion(db.Model):
        __tablename__ = 'mail_template_versions'
        id = db.Column(db.Integer, primary_key=True)
        template_id = db.Column(db.Integer, db.ForeignKey('mail_templates.id'), nullable=False)
        revision = db.Column(db.Integer, nullable=False)
        snapshot = db.Column(db.Text, nullable=False)
        actor_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
        created_at = db.Column(db.DateTime, nullable=False, default=now)
        __table_args__ = (db.UniqueConstraint('template_id', 'revision'),)

    class TemplateImportReview(db.Model):
        __tablename__ = 'mail_template_imports'
        id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        actor_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
        payload = db.Column(db.Text, nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False, default=lambda: now() + timedelta(minutes=15))
        result = db.Column(db.Text)

    def catalog_selection(ids):
        if not isinstance(ids, list) or len(ids) > MAX_ATTACHMENTS or any(not isinstance(key,str) or not re.fullmatch(r'[0-9a-f]{64}',key) for key in ids):
            raise ValueError('Choose up to three PDFs from the attachment catalog.')
        ids = list(dict.fromkeys(ids))
        rows = db.session.query(TemplateAsset.id, TemplateAsset.name, db.func.length(TemplateAsset.payload)).filter(TemplateAsset.id.in_(ids)).all()
        found = {key: {'id': key, 'name': name, 'bytes': size} for key,name,size in rows}
        if len(found) != len(ids):
            raise ValueError('A selected catalog PDF is unavailable. Refresh the catalog.')
        files = [found[key] for key in ids]
        if sum(item['bytes'] for item in files) > MAX_TEMPLATE_BYTES:
            raise ValueError('Selected PDFs must total at most 15 MB.')
        return files

    def user():
        return db.session.get(User, int(get_jwt_identity()))

    def serial(row):
        version = MailTemplateVersion.query.filter_by(template_id=row.id, revision=row.revision).one()
        return {**json.loads(version.snapshot), 'id': row.id, 'revision': row.revision,
                'version_id': version.id, 'archived': row.archived}

    def store_approved_pdf(filename):
        if filename not in APPROVED_PDFS:
            raise ValueError('Choose a PDF from the approved attachment list.')
        path = PDF_DIRECTORY / filename
        if not path.is_file() or path.stat().st_size > MAX_PDF_BYTES:
            raise ValueError('The approved PDF is missing or exceeds 10 MB.')
        payload = path.read_bytes()
        if not payload.startswith(b'%PDF-') or len(payload) > MAX_PDF_BYTES:
            raise ValueError('The approved file must be a PDF of at most 10 MB.')
        asset_id = hashlib.sha256(payload).hexdigest()
        if db.session.get(TemplateAsset, asset_id) is None:
            try:
                with db.session.begin_nested():
                    db.session.add(TemplateAsset(id=asset_id, name=filename, payload=payload))
                    db.session.flush()
            except IntegrityError:
                pass  # Another admin saved the same immutable bytes.
        return db.session.get(TemplateAsset, asset_id)

    def checked(data):
        if not isinstance(data, dict):
            raise ValueError('Enter a template object.')
        name = data.get('name')
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 180:
            raise ValueError('Enter a template name of 1 to 180 characters.')
        kind, step = data.get('kind'), data.get('step', 0)
        if kind not in ('initial', 'followup') or type(step) is not int or step not in ((0,) if kind == 'initial' else (1, 2, 3)):
            raise ValueError('Choose an intro or follow-up step 1, 2 or 3.')
        if data.get('audience') not in AUDIENCES:
            raise ValueError('Choose a supported audience.')
        validate_copy(data.get('subject'), data.get('body'))
        filename, asset_id = data.get('attachment_file'), data.get('attachment_id')
        if filename:
            asset_id = store_approved_pdf(filename).id
        ids = data.get('attachment_ids')
        if ids is None:
            ids = [asset_id] if asset_id else []
        if not isinstance(ids, list) or len(ids) > MAX_ATTACHMENTS or any(not isinstance(i, str) or not re.fullmatch(r'[0-9a-f]{64}', i) for i in ids):
            raise ValueError('Choose up to three saved PDF attachments.')
        if filename and asset_id not in ids:
            ids = [*ids, asset_id]
        if len(ids) > MAX_ATTACHMENTS:
            raise ValueError('Choose up to three saved PDF attachments.')
        ids = list(dict.fromkeys(ids))
        assets = [db.session.get(TemplateAsset, key) for key in ids]
        if any(asset is None for asset in assets):
            raise ValueError('A selected attachment is unavailable.')
        if sum(len(asset.payload) for asset in assets) > MAX_TEMPLATE_BYTES:
            raise ValueError('Template PDFs must total at most 15 MB.')
        if data.get('attachments') and not assets:
            raise ValueError('Select approved attachments explicitly.')
        files = [{'id': asset.id, 'name': asset.name, 'bytes': len(asset.payload)} for asset in assets]
        return {key: data[key] for key in ('name', 'kind', 'audience', 'subject', 'body')} | {
            'step': step, 'attachment_id': ids[0] if ids else None, 'attachment_ids': ids, 'attachments': files}

    def append(row, snapshot, actor):
        version = MailTemplateVersion(template_id=row.id, revision=row.revision,
                                      snapshot=json.dumps({**snapshot, 'archived': row.archived}, ensure_ascii=False), actor_id=actor.id)
        db.session.add(version)

    def resolve(data):
        tid = data.get('template_id')
        if tid is None:
            if data.get('template_revision') is not None:
                raise ValueError('Choose a template before its revision.')
            return None
        if type(tid) is not int or type(data.get('template_revision')) is not int:
            raise ValueError('Choose a template and its revision.')
        row = MailTemplate.query.filter_by(id=tid).with_for_update().first()
        if not row or row.archived or row.revision != data['template_revision']:
            raise ValueError('The shared template changed or was archived. Choose it again.')
        selected = serial(row)
        if selected['kind'] != data.get('kind'):
            raise ValueError('Choose a template matching this message type.')
        if data.get('attachments'):
            raise ValueError('Use the attachment saved in the shared template.')
        # Validate edited batch copy too, not just the library version.
        validate_copy(data.get('subject') if data.get('subject') is not None else selected['subject'],
                      data.get('body') if data.get('body') is not None else selected['body'])
        return selected

    @app.get('/api/outreach/template-assets')
    @jwt_required()
    def template_assets():
        actor = user()
        if not actor:
            return jsonify(error='User not found'), 404
        files = []
        for filename in APPROVED_PDFS:
            path = PDF_DIRECTORY / filename
            if path.is_file() and path.stat().st_size <= MAX_PDF_BYTES:
                with path.open('rb') as handle:
                    if handle.read(5) == b'%PDF-':
                        files.append({'filename': filename, 'bytes': path.stat().st_size})
        return jsonify(items=files, saved=[{'id': key, 'name': name, 'bytes': size} for key, name, size in db.session.query(TemplateAsset.id, TemplateAsset.name, db.func.length(TemplateAsset.payload)).all()], max_bytes=MAX_PDF_BYTES)

    @app.post('/api/outreach/template-assets/publish')
    @jwt_required()
    def publish_template_asset():
        actor = user()
        if not actor or not actor.admin:
            return jsonify(error='Admin access required'), 403
        data = request.get_json(silent=True)
        if not isinstance(data,dict) or set(data) != {'filename'}:
            return jsonify(error='Choose an existing PSA PDF'), 400
        try:
            asset = store_approved_pdf(data['filename'])
        except ValueError as error:
            db.session.rollback()
            return jsonify(error=str(error)), 400
        db.session.commit()
        return jsonify(id=asset.id,name=asset.name,bytes=len(asset.payload)), 201

    @app.post('/api/outreach/template-assets')
    @jwt_required()
    def upload_template_asset():
        actor = user()
        if not actor or not actor.admin:
            return jsonify(error='Admin access required'), 403
        db.session.rollback()  # Release the auth lookup connection before reading an upload.
        uploaded = request.files.get('file')
        name = secure_filename(uploaded.filename or '') if uploaded else ''
        if not uploaded or not name.lower().endswith('.pdf') or len(name) > 180:
            return jsonify(error='Choose a PDF with a valid filename'), 400
        payload = uploaded.stream.read(MAX_PDF_BYTES + 1)
        if not payload.startswith(b'%PDF-') or len(payload) > MAX_PDF_BYTES:
            return jsonify(error='Upload a PDF of at most 10 MB'), 400
        key = hashlib.sha256(payload).hexdigest()
        asset = db.session.get(TemplateAsset, key)
        if not asset:
            try:
                with db.session.begin_nested():
                    db.session.add(TemplateAsset(id=key, name=name, payload=payload)); db.session.flush()
            except IntegrityError:
                pass
            asset = db.session.get(TemplateAsset, key)
        db.session.commit()
        return jsonify(id=asset.id, name=asset.name, bytes=len(asset.payload)), 201

    @app.get('/api/outreach/template-assets/<string:key>')
    @jwt_required()
    def download_template_asset(key):
        actor = user()
        if not actor:
            return jsonify(error='User not found'), 404
        asset = db.session.get(TemplateAsset, key)
        if not asset:
            return jsonify(error='PDF not found'), 404
        response = send_file(io.BytesIO(asset.payload), mimetype='application/pdf', as_attachment=True, download_name=asset.name)
        response.headers['Cache-Control'] = 'private, no-store'
        return response

    def import_snapshot(row):
        if not isinstance(row,dict) or row.get('attachment_file'):
            raise ValueError('Use existing catalog attachment_ids or select PDFs after importing')
        row = dict(row)
        names = ['Principal / AP / school staff (short forward request)', 'PTA / PTO officers (direct ask)',
                 'Enrichment / ASEP / after-school coordinator (scheduling-focused)', 'Trunk-or-Treat contacts (warm)']
        stable = ['principal_ap','pta_pto','enrichment','trunk_or_treat']
        if row.get('audience') in names:
            row['audience'] = stable[names.index(row['audience'])]
        if 'step' not in row and type(row.get('send_on_day')) is int and row['send_on_day'] in (0,4,10,17):
            row['step'] = (0,4,10,17).index(row['send_on_day'])
        return checked(row)

    def snapshot_hash(snapshot):
        return hashlib.sha256(json.dumps(snapshot,sort_keys=True,ensure_ascii=False).encode()).hexdigest()

    @app.post('/api/outreach/template-imports/preview')
    @jwt_required()
    def template_import_preview():
        actor = user()
        if not actor or not actor.admin:
            return jsonify(error='Admin access required'), 403
        uploaded = request.files.get('file')
        if not uploaded or not (uploaded.filename or '').lower().endswith('.json'):
            return jsonify(error='Upload a UTF-8 JSON template file'), 400
        raw = uploaded.stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return jsonify(error='Template imports are limited to 1 MB'), 400
        try:
            document = json.loads(raw.decode('utf-8-sig'))
            rows = document.get('templates', [document]) if isinstance(document,dict) else document
            if not isinstance(rows,list) or not 1 <= len(rows) <= 100:
                raise ValueError('Upload between 1 and 100 templates')
            plans, errors, seen = [], [], set()
            source_keys = {}
            if SEED.is_file():
                for item in json.loads(SEED.read_text(encoding='utf-8'))['templates']:
                    canonical = import_snapshot(item)
                    source_keys[snapshot_hash(canonical)] = f"winter2027:{canonical['audience']}:{canonical['step']}"
            for index, row in enumerate(rows,1):
                try:
                    snapshot = import_snapshot(row)
                    digest = snapshot_hash(snapshot)
                    key = source_keys.get(digest, 'upload:' + digest)
                    duplicate = key in seen
                    seen.add(key)
                    plans.append({'key':key,'snapshot':snapshot,'duplicate':duplicate})
                except (ValueError, TypeError) as error:
                    errors.append({'row':index,'error':str(error)})
            if errors:
                return jsonify(error='Fix invalid template rows before importing', rows=errors), 400
        except (UnicodeDecodeError,json.JSONDecodeError,ValueError) as error:
            return jsonify(error=str(error)), 400
        provenance = {'filename':secure_filename(uploaded.filename),'sha256':hashlib.sha256(raw).hexdigest()}
        review = TemplateImportReview(actor_id=actor.id,payload=json.dumps({'plans':plans,'provenance':provenance},ensure_ascii=False))
        db.session.add(review);db.session.commit()
        existing = {row.source_key for row in MailTemplate.query.filter(MailTemplate.source_key.in_(seen)).all()}
        return jsonify(id=review.id,filename=provenance['filename'],total=len(plans),
            new=sum(not plan['duplicate'] and plan['key'] not in existing for plan in plans),
            items=[{'name':plan['snapshot']['name'],'kind':plan['snapshot']['kind'],'audience':plan['snapshot']['audience'],
                    'attachments':[item['name'] for item in plan['snapshot']['attachments']],
                    'action':'skip existing' if plan['duplicate'] or plan['key'] in existing else 'create'} for plan in plans])

    @app.post('/api/outreach/template-imports/<string:rid>/commit')
    @jwt_required()
    def template_import_commit(rid):
        actor = user()
        if not actor or not actor.admin:
            return jsonify(error='Admin access required'), 403
        review = TemplateImportReview.query.filter_by(id=rid,actor_id=actor.id).with_for_update().first()
        if not review:
            return jsonify(error='Import review not found'), 404
        if review.result:
            return jsonify(json.loads(review.result))
        if review.expires_at < now():
            return jsonify(error='Template import review expired. Upload again.'), 409
        payload = json.loads(review.payload)
        added = 0
        for plan in sorted(payload['plans'],key=lambda item:item['key']):
            if plan['duplicate'] or MailTemplate.query.filter_by(source_key=plan['key']).first():
                continue
            try:
                snapshot = checked(plan['snapshot'])
            except ValueError as error:
                db.session.rollback()
                return jsonify(error=str(error)), 409
            snapshot['provenance'] = payload['provenance']
            try:
                with db.session.begin_nested():
                    row = MailTemplate(source_key=plan['key'])
                    db.session.add(row);db.session.flush();append(row,snapshot,actor);db.session.flush()
                added += 1
            except IntegrityError:
                pass
        result = {'added':added,'skipped':len(payload['plans'])-added}
        review.result = json.dumps(result);db.session.commit()
        return jsonify(result)

    @app.get('/api/outreach/templates')
    @jwt_required()
    def template_list():
        actor = user()
        if not actor:
            return jsonify(error='User not found'), 404
        rows = MailTemplate.query
        if not (actor.admin and request.args.get('include_archived') == '1'):
            rows = rows.filter_by(archived=False)
        return jsonify(items=[serial(row) for row in rows.order_by(MailTemplate.id).all()])

    @app.post('/api/outreach/templates')
    @jwt_required()
    def template_create():
        actor = user()
        if not actor or not actor.admin:
            return jsonify(error='Admin access required'), 403
        try:
            snapshot = checked(request.get_json(silent=True))
        except ValueError as exc:
            db.session.rollback()
            return jsonify(error=str(exc)), 400
        row = MailTemplate()
        db.session.add(row); db.session.flush(); append(row, snapshot, actor); db.session.commit()
        return jsonify(serial(row)), 201

    @app.put('/api/outreach/templates/<int:tid>')
    @jwt_required()
    def template_edit(tid):
        actor = user()
        if not actor or not actor.admin:
            return jsonify(error='Admin access required'), 403
        data = request.get_json(silent=True)
        try:
            snapshot = checked(data)
        except ValueError as exc:
            db.session.rollback()
            return jsonify(error=str(exc)), 400
        row = db.session.get(MailTemplate, tid)
        if not row:
            return jsonify(error='Template not found'), 404
        original = serial(row)
        if original.get('provenance'):
            snapshot['provenance'] = original['provenance']
        rev = data.get('revision')
        if type(rev) is not int or type(data.get('archived', False)) is not bool:
            return jsonify(error='Include the current revision and an archive flag'), 400
        changed = db.session.execute(update(MailTemplate).where(MailTemplate.id == tid, MailTemplate.revision == rev).values(
            revision=rev + 1, archived=data.get('archived', False))).rowcount
        if not changed:
            db.session.rollback()
            return jsonify(error='This template changed. Reload before saving.'), 409
        db.session.refresh(row); append(row, snapshot, actor); db.session.commit()
        return jsonify(serial(row))

    @app.get('/api/outreach/templates/<int:tid>/versions')
    @jwt_required()
    def template_versions(tid):
        actor = user()
        if not actor or not actor.admin:
            return jsonify(error='Admin access required'), 403
        return jsonify(items=[{**json.loads(v.snapshot), 'revision': v.revision, 'actor_id': v.actor_id,
                               'created_at': v.created_at.isoformat() + 'Z'} for v in
                              MailTemplateVersion.query.filter_by(template_id=tid).order_by(MailTemplateVersion.revision.desc())])

    @app.post('/api/outreach/templates/seed-winter-2027')
    @jwt_required()
    def template_seed():
        if requested_area() == 'business':
            return jsonify(error='Winter school templates are only available in School Sales. Create a sponsorship template here.'),400
        actor = user()
        if not actor or not actor.admin:
            return jsonify(error='Admin access required'), 403
        raw = SEED.read_bytes()
        source = json.loads(raw)
        audiences = list(dict.fromkeys(item['audience'] for item in source['templates']))
        audience_ids = ['principal_ap', 'pta_pto', 'enrichment', 'trunk_or_treat']
        added = 0
        try:
            # Savepoints plus unique source keys make simultaneous seed requests safe.
            for item in source['templates']:
                index = audiences.index(item['audience'])
                step = [0, 4, 10, 17].index(item['send_on_day'])
                key = f'winter2027:{audience_ids[index]}:{step}'
                if MailTemplate.query.filter_by(source_key=key).first():
                    continue
                snapshot = checked({**item, 'audience': audience_ids[index], 'step': step})
                snapshot['provenance'] = {'source': source['source'], 'sha256': hashlib.sha256(raw).hexdigest(),
                                          'suggested_day': item['send_on_day']}
                try:
                    with db.session.begin_nested():
                        row = MailTemplate(source_key=key)
                        db.session.add(row); db.session.flush(); append(row, snapshot, actor); db.session.flush()
                    added += 1
                except IntegrityError:
                    pass
            db.session.commit()
        except (ValueError, KeyError):
            db.session.rollback()
            return jsonify(error='The source template file failed validation.'), 400
        return jsonify(added=added, existing=16-added, automatic_schedule_changed=False)

    return MailTemplate, MailTemplateVersion, TemplateAsset, resolve, attachment_payload, catalog_selection
