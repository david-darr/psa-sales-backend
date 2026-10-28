"""Import the PSA Drive audit (psa_schools.csv + psa_history.csv) into PSA Sales.

The audit already uses PSA Sales stage names. Each school row is upserted into
sales_schools (matched by primary email, else by normalised name), and each history
row becomes a school activity dated when it happened. Dry run by default.

    python -m api.maintenance.import_drive_audit DIR --fallback-owner admin@example.com
    python -m api.maintenance.import_drive_audit DIR --fallback-owner admin@example.com --apply

Rules:
  * owner_email that matches an account owns the school; otherwise --fallback-owner
    holds it and the notes say "Audit owner: <email>". Re-running after that rep signs
    up moves the school to them. --owner "School name=email" (repeatable) assigns
    schools the audit could not (for example a rep whose email was not in Drive).
  * Closed clients keep closed_at from the file. A blank closed_at stays blank: the
    import never pretends a school closed today, so commission periods stay accurate.
  * Stages only move forward on re-runs; a manual edit in the app is never downgraded.
  * --visits-as-contacted turns schools whose only "meeting" is a flyer drop or visit
    into "contacted" (audit scope decision 1).
"""

import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime, timezone

RANK = {'pending': 0, 'contacted': 1, 'replied': 2, 'meeting': 3, 'not_interested': 3, 'former': 4, 'partner': 5}
KINDS = {'meeting': 'meeting', 'call': 'call', 'note': 'note', 'email_out': 'note'}
MARKER = '[audit 2026-10-28]'


def read(path):
    with open(path, newline='', encoding='utf-8-sig') as handle:
        return [{k: (v or '').strip() for k, v in row.items() if k} for row in csv.DictReader(handle)]


def day(value):
    if not value:
        return None
    try:
        return datetime.strptime(value[:10], '%Y-%m-%d')
    except ValueError:
        return None


def emails(primary, extra, valid):
    found = []
    for item in [primary] + re.split(r'[;,\s]+', extra or ''):
        item = item.strip().lower()
        if item and valid(item) and item not in found:
            found.append(item)
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('directory', help='folder holding psa_schools.csv and psa_history.csv')
    parser.add_argument('--fallback-owner', required=True)
    parser.add_argument('--owner', action='append', default=[], help='"School name=rep email"')
    parser.add_argument('--visits-as-contacted', action='store_true')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    os.environ.setdefault('PSA_DISABLE_SCHEDULER', 'true')

    from api import api as app_module
    db, User, School, Activity = app_module.db, app_module.User, app_module.SalesSchool, app_module.SchoolActivity
    norm, valid = app_module.normalize_name, app_module.valid_email

    schools_rows = read(os.path.join(args.directory, 'psa_schools.csv'))
    history_rows = read(os.path.join(args.directory, 'psa_history.csv'))
    overrides = {}
    for item in args.owner:
        name, _, email = item.rpartition('=')
        overrides[norm(name)] = email.strip().lower()

    with app_module.app.app_context():
        users = {u.email.lower(): u for u in User.query.all()}
        fallback = users.get(args.fallback_owner.strip().lower())
        if not fallback:
            sys.exit('Fallback owner not found. Use the email of an existing account.')

        existing = School.query.all()
        by_email, by_name = {}, {}
        for school in existing:
            for item in school.get_all_emails():
                if item and item.strip():
                    by_email.setdefault(item.strip().lower(), school)
            by_name.setdefault(norm(school.school_name), school)

        # Emails the audit gives to more than one school (shared PTA or coordinator
        # inboxes) cannot identify a school, so only names match those rows.
        counts = {}
        for row in schools_rows:
            for item in emails(row['email'], row['additional_emails'], valid):
                counts[item] = counts.get(item, 0) + 1
        shared = {item for item, count in counts.items() if count > 1}

        visited_only = set()
        if args.visits_as_contacted:
            meetings = {}
            for row in history_rows:
                if row['kind'] == 'meeting':
                    meetings.setdefault(norm(row['school_name']), []).append(row['detail'].lower())
            visited_only = {name for name, details in meetings.items()
                            if all(re.search(r'visit|flyer', d) for d in details)}

        stats = {'created': 0, 'updated': 0, 'unchanged': 0, 'invalid': 0,
                 'held_by_fallback': 0, 'activities_added': 0, 'activities_skipped': 0}
        stages, waiting_owners, problems = {}, {}, []
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        imported = {}

        for row in schools_rows:
            name = row['school_name']
            stage = row['status']
            if not name or stage not in RANK:
                stats['invalid'] += 1
                problems.append(f'{name or "(blank)"}: unknown status {stage!r}')
                continue
            key = norm(name)
            if stage == 'meeting' and key in visited_only:
                stage = 'contacted'
            owner_email = overrides.get(key) or row['owner_email'].lower()
            owner = users.get(owner_email) if owner_email else None
            if owner_email and not owner:
                waiting_owners[owner_email] = waiting_owners.get(owner_email, 0) + 1
            if not owner:
                stats['held_by_fallback'] += 1
            owner = owner or fallback

            mails = emails(row['email'], row['additional_emails'], valid)
            notes = [row['notes']]
            if row['outcome_reason']:
                notes.append(f'Outcome: {row["outcome_reason"]}')
            notes.append(f'Audit confidence: {row["confidence"] or "unknown"}')
            if owner_email and users.get(owner_email) is None:
                notes.append(f'Audit owner: {owner_email}')
            if row['source_url']:
                notes.append('Sources: ' + ' '.join(row['source_url'].split(';')))
            note_text = MARKER + '\n' + '\n'.join(part for part in notes if part)

            school = by_name.get(key) or next(
                (by_email[m] for m in mails if m in by_email and m not in shared), None)
            changes = []
            if school is None:
                school = School(school_name=name, email=mails[0] if mails else '',
                                contact_name=row['contact_name'] or None, phone=row['phone'] or None,
                                address=row['address'] or None, website=row['website'] or None,
                                school_type=row['school_type'] if row['school_type'] in ('preschool', 'elementary', 'private') else 'preschool',
                                status=stage, user_id=owner.id, notes=note_text,
                                next_action=row['next_action'] or None, next_action_at=day(row['next_action_at']),
                                created_at=now)
                school.set_additional_emails(mails[1:])
                closed = day(row['closed_at'])
                if stage in ('partner', 'former') and closed:
                    school.closed_at = closed.replace(hour=12, tzinfo=timezone.utc)
                    school.closed_by_id = owner.id
                db.session.add(school)
                db.session.flush()
                changes.append('new')
                stats['created'] += 1
            else:
                if owner.id != school.user_id and owner is not fallback:
                    school.user_id = owner.id
                    changes.append(f'owner -> {owner.name}')
                if RANK[stage] > RANK.get(school.status or 'pending', 0):
                    school.status = stage
                    changes.append(f'stage -> {stage}')
                for field, value in (('contact_name', row['contact_name']), ('phone', row['phone']),
                                     ('address', row['address']), ('next_action', row['next_action'])):
                    if value and not getattr(school, field):
                        setattr(school, field, value)
                        changes.append(field)
                if MARKER not in (school.notes or ''):
                    school.notes = '\n\n'.join(filter(None, [school.notes, note_text]))
                    changes.append('notes')
                stats['updated' if changes else 'unchanged'] += 1
            imported[key] = school
            stages[school.status] = stages.get(school.status, 0) + 1

        seen = {(a.sales_school_id, a.created_at, a.detail) for a in
                Activity.query.filter(Activity.sales_school_id.in_([s.id for s in imported.values()])).all()} if imported else set()
        for row in history_rows:
            school = imported.get(norm(row['school_name']))
            when = day(row['occurred_at'])
            if not school or not when or not row['detail']:
                stats['activities_skipped'] += 1
                continue
            kind = KINDS.get(row['kind'], 'note')
            detail = ('Email sent: ' if row['kind'] == 'email_out' else '') + row['detail']
            detail = detail[:2000]
            when = when.replace(hour=12)
            if (school.id, when, detail) in seen:
                stats['activities_skipped'] += 1
                continue
            db.session.add(Activity(sales_school_id=school.id, actor_id=fallback.id, kind=kind,
                                    detail=detail, created_at=when))
            seen.add((school.id, when, detail))
            stats['activities_added'] += 1

        print(json.dumps({'mode': 'APPLY' if args.apply else 'DRY RUN', **stats,
                          'stages_after': stages, 'owners_without_account': waiting_owners}, indent=2))
        for line in problems[:20]:
            print('  problem:', line)
        if args.apply:
            db.session.commit()
            print('Committed.')
        else:
            db.session.rollback()
            print('Rolled back. Re-run with --apply to write.')


if __name__ == '__main__':
    main()
