"""Import a PSA school audit (schools in contact and current clients) into sales_schools.

Reads a .csv or .xlsx (every sheet), maps columns by name, and upserts each school:
an existing school with the same email, or the same name (and address when both have
one), is updated instead of duplicated. Dry run by default; nothing is written
without --apply.

    python -m api.maintenance.import_school_audit audit.xlsx --fallback-owner admin@example.com
    python -m api.maintenance.import_school_audit audit.xlsx --fallback-owner admin@example.com --apply

Columns (case and spacing ignored; only a school name is required):
    school / school name / name, email, contact / director, phone, address,
    type (preschool, elementary, private), rep / owner / sales rep (name or email),
    status / stage, deal value / value, notes, sheet name used as a status hint.

Status mapping: anything meaning "current client" becomes Active client (closed, with
the rep as closer); "former" becomes Former client; "meeting" becomes Meeting;
"not interested" becomes Closed; everything else (in contact, contacted, emailed, lead)
becomes Contacted. A school whose rep has no account yet goes to --fallback-owner with
"Audit rep: <name>" in its notes. Re-running after that rep signs up moves it to them.
Stages only move forward: the import never downgrades a client back to Contacted.
"""

import argparse
import csv
import os
import re
import sys
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

COLUMNS = {
    'name': ('school', 'school name', 'schoolname', 'name', 'account', 'organization', 'center', 'centre'),
    'email': ('email', 'email address', 'school email', 'contact email', 'e-mail'),
    'contact': ('contact', 'contact name', 'director', 'principal', 'point of contact', 'poc'),
    'phone': ('phone', 'phone number', 'telephone', 'tel'),
    'address': ('address', 'location', 'school address', 'street address'),
    'city': ('city', 'town'),
    'state': ('state', 'st'),
    'zip': ('zip', 'zip code', 'postal code'),
    'type': ('type', 'school type', 'category'),
    'rep': ('rep', 'sales rep', 'owner', 'assigned to', 'salesperson', 'coach', 'account owner', 'rep email'),
    'status': ('status', 'stage', 'relationship', 'client status'),
    'value': ('deal value', 'value', 'contract value', 'revenue', 'amount'),
    'notes': ('notes', 'note', 'comments', 'details'),
}
RANK = {'pending': 0, 'contacted': 1, 'replied': 2, 'meeting': 3, 'not_interested': 3, 'former': 4, 'partner': 5}


def key(text):
    return re.sub(r'[^a-z0-9]+', ' ', str(text or '').lower()).strip()


def stage_for(raw, sheet=''):
    """A row's own status wins; the sheet name (e.g. "Schools currently in") is the fallback."""
    return stage_from_text(key(raw) or key(sheet))


def stage_from_text(text):
    if re.search(r'\bformer\b|\bpast client|\bchurn|\blost client', text):
        return 'former'
    if re.search(r'\bnot interested|\bdeclined|\bdead\b', text):
        return 'not_interested'
    if re.search(r'\bmeeting|\bdemo\b|\bscheduled', text):
        return 'meeting'
    # Check prospect wording before "client" so "potential client" stays a lead.
    if re.search(r'\bin contact|\bprospect|\bpotential|\blead\b|\breached out|\bpitch|\bpipeline', text):
        return 'contacted'
    if re.search(r'\bcurrent|\bactive\b|\bclient\b|\bpartner|\bsigned|\bcurrently in\b|\bwon\b|\brunning', text):
        return 'partner'
    if re.search(r'\brepl|\bresponded|\bconversation', text):
        return 'replied'
    return 'contacted'


def school_type(raw, name):
    text = key(f'{raw} {name}')
    if re.search(r'elementary|\bes\b|primary', text):
        return 'elementary'
    if re.search(r'catholic|private|academy|parish|st |saint|christian|episcopal|lutheran', text) and 'preschool' not in text:
        return 'private'
    return 'preschool'


def read_rows(path):
    """Yield (sheet_name, {header: value}) for every data row."""
    if path.lower().endswith(('.xlsx', '.xlsm')):
        import openpyxl
        book = openpyxl.load_workbook(path, read_only=True, data_only=True)
        for sheet in book.worksheets:
            rows = sheet.iter_rows(values_only=True)
            headers = None
            for row in rows:
                cells = ['' if cell is None else str(cell).strip() for cell in row]
                if headers is None:
                    if any(key(cell) in COLUMNS['name'] for cell in cells):
                        headers = cells
                    continue
                if any(cells):
                    yield sheet.title, dict(zip(headers, cells))
    else:
        with open(path, newline='', encoding='utf-8-sig') as handle:
            for row in csv.DictReader(handle):
                yield '', {k: (v or '').strip() for k, v in row.items() if k}


def pick(row, field):
    for header, value in row.items():
        if key(header) in COLUMNS[field] and value:
            return value
    return ''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('path')
    parser.add_argument('--fallback-owner', required=True, help='email of the account that holds schools whose rep has no account yet')
    parser.add_argument('--apply', action='store_true', help='write changes (default is a dry run)')
    args = parser.parse_args(argv)
    os.environ.setdefault('PSA_DISABLE_SCHEDULER', 'true')

    from api import api as app_module
    from api.portfolio import set_school_status
    db, User, School, Activity = app_module.db, app_module.User, app_module.SalesSchool, app_module.SchoolActivity

    with app_module.app.app_context():
        users = User.query.all()
        by_email = {u.email.lower(): u for u in users}
        by_name = {key(u.name): u for u in users}
        by_first = {}
        for u in users:
            by_first.setdefault(key(u.name).split(' ')[0], []).append(u)
        fallback = by_email.get(args.fallback_owner.strip().lower())
        if not fallback:
            sys.exit('Fallback owner not found. Use the email of an existing account.')

        def rep_for(raw):
            text = key(raw)
            if not text:
                return None
            if '@' in raw:
                return by_email.get(raw.strip().lower())
            if text in by_name:
                return by_name[text]
            first = by_first.get(text.split(' ')[0], [])
            return first[0] if len(first) == 1 and len(text.split(' ')) == 1 else None

        existing = School.query.all()
        by_school_email, by_school_name = {}, {}
        for school in existing:
            for item in school.get_all_emails():
                if item and item.strip():
                    by_school_email[item.strip().lower()] = school
            by_school_name.setdefault(app_module.normalize_name(school.school_name), []).append(school)

        stats = {'rows': 0, 'created': 0, 'updated': 0, 'unchanged': 0, 'skipped': 0, 'fallback_owner': 0}
        unmatched_reps, report, seen = {}, [], set()
        now = datetime.now(timezone.utc)
        for sheet, row in read_rows(args.path):
            name = pick(row, 'name')
            if not name or key(name) in ('total', 'totals'):
                stats['skipped'] += 1
                continue
            stats['rows'] += 1
            email = pick(row, 'email').split(';')[0].split(',')[0].strip().lower()
            if email and not app_module.valid_email(email):
                email = ''
            address = pick(row, 'address')
            extra = ', '.join(part for part in (pick(row, 'city'), pick(row, 'state'), pick(row, 'zip')) if part)
            if extra and extra.lower() not in address.lower():
                address = f'{address}, {extra}' if address else extra
            rep_raw = pick(row, 'rep')
            rep = rep_for(rep_raw)
            if rep_raw and not rep:
                unmatched_reps[rep_raw] = unmatched_reps.get(rep_raw, 0) + 1
            owner = rep or fallback
            stage = stage_for(pick(row, 'status'), sheet)
            value = None
            raw_value = re.sub(r'[^0-9.]', '', pick(row, 'value'))
            if raw_value:
                try:
                    value = Decimal(raw_value).quantize(Decimal('0.01'))
                except InvalidOperation:
                    value = None
            norm = app_module.normalize_name(name)
            if (norm, email) in seen:
                stats['skipped'] += 1
                continue
            seen.add((norm, email))

            school = by_school_email.get(email) if email else None
            if school is None:
                candidates = by_school_name.get(norm, [])
                same_place = [s for s in candidates if not address or not s.address
                              or app_module.normalize_name(s.address) == app_module.normalize_name(address)]
                school = same_place[0] if len(same_place) == 1 else None
            audit_note = f'Audit rep: {rep_raw}' if rep_raw and not rep else ''
            changes = []
            if school is None:
                school = School(school_name=name.strip(), email=email, contact_name=pick(row, 'contact') or None,
                                phone=pick(row, 'phone') or None, address=address or None,
                                school_type=school_type(pick(row, 'type'), name), user_id=owner.id, status='pending',
                                notes='\n'.join(filter(None, [pick(row, 'notes'), audit_note])) or None)
                db.session.add(school)
                db.session.flush()
                by_school_name.setdefault(norm, []).append(school)
                if email:
                    by_school_email[email] = school
                changes.append('new')
                stats['created'] += 1
            else:
                for field, value_in in (('contact_name', pick(row, 'contact')), ('phone', pick(row, 'phone')),
                                        ('address', address), ('email', email)):
                    if value_in and not getattr(school, field):
                        setattr(school, field, value_in)
                        changes.append(field)
                if rep and school.user_id != rep.id:
                    school.user_id = rep.id
                    changes.append(f'owner -> {owner.name}')
                if audit_note and audit_note not in (school.notes or ''):
                    school.notes = '\n'.join(filter(None, [school.notes, audit_note]))
                    changes.append('note')
            if RANK.get(stage, 0) > RANK.get(school.status or 'pending', 0):
                set_school_status(school, stage, owner.id)
                changes.append(f'stage -> {stage}')
            if value is not None and school.deal_value is None and stage in ('partner', 'former'):
                school.deal_value = value
                changes.append('deal value')
            if not rep:
                stats['fallback_owner'] += 1
            if changes and 'new' not in changes:
                stats['updated'] += 1
            elif not changes:
                stats['unchanged'] += 1
            if changes:
                db.session.add(Activity(sales_school_id=school.id, actor_id=fallback.id, kind='note',
                                        detail='Updated from the PSA school audit: ' + ', '.join(changes),
                                        created_at=now.replace(tzinfo=None)))
            report.append((name, school.status, owner.name, ', '.join(changes) or 'no change'))

        print(f"{'APPLYING' if args.apply else 'DRY RUN'}: {stats}")
        if unmatched_reps:
            print('Reps without an account (schools held by the fallback owner):')
            for rep_raw, count in sorted(unmatched_reps.items(), key=lambda item: -item[1]):
                print(f'  {rep_raw}: {count}')
        stage_counts = {}
        for _, stage, _, _ in report:
            stage_counts[stage] = stage_counts.get(stage, 0) + 1
        print('Resulting stages:', stage_counts)
        for line in report[:40]:
            print('  ' + ' | '.join(str(part) for part in line))
        if len(report) > 40:
            print(f'  ... {len(report) - 40} more')
        if args.apply:
            db.session.commit()
            print('Committed.')
        else:
            db.session.rollback()
            print('Rolled back. Re-run with --apply to write.')


if __name__ == '__main__':
    main()
