"""Sales-area boundaries shared by the website, agent API and durable mail jobs.

Existing IDs and foreign keys stay stable. No record is moved by changing a UI
preference. HTTP queries default to schools; workers deliberately process both.
Workspace filtering supplements, never replaces, employee/owner authorization.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps

from flask import has_request_context, jsonify, request
from sqlalchemy import event
from sqlalchemy.orm import with_loader_criteria

AREAS = ('school', 'business')
TABLES = (
    'sales_schools', 'sales_tasks', 'sent_emails', 'outreach_batches',
    'outreach_campaigns', 'outreach_contact_reviews', 'mail_templates',
    'mail_template_imports', 'mail_sequences', 'mail_sequence_enrollments',
    'mail_sequence_reviews', 'approved_campaign_plans', 'agent_outreach_drafts',
    'contact_imports', 'school_assignment_reviews',
)
_unscoped = ContextVar('psa_all_sales_areas', default=False)


def requested_area():
    if not has_request_context():
        return None
    return request.headers.get('X-PSA-Workspace') or request.args.get('workspace') or 'school'


@contextmanager
def all_sales_areas():
    """Internal mailbox-wide quotas and suppression must span both workspaces."""
    token = _unscoped.set(True)
    try:
        yield
    finally:
        _unscoped.reset(token)


def across_sales_areas(function):
    @wraps(function)
    def run(*args, **kwargs):
        with all_sales_areas():
            return function(*args, **kwargs)
    return run


def record_in_area(record):
    return record is not None and (not has_request_context() or _unscoped.get() or record.sales_workspace == requested_area())


def sales_area_error(endpoint=None):
    """Validate direct requests and delegated AI handlers with the same rules."""
    area = requested_area()
    if area not in AREAS:
        return jsonify(error='Choose School Sales or Business Sales', code='invalid_workspace'), 400
    if area == 'business' and (endpoint or request.endpoint) in (
        'crm_directory', 'map_schools', 'refresh_map_schools',
    ):
        return jsonify(error='This school reference source is only available in School Sales'), 400


def register_sales_workspaces(app, db, svc):
    # Declarative extension keeps the domain boundary in one place. Every entry
    # has a matching additive migration; no columns are created on app startup.
    models = {m.local_table.name: m.class_ for m in db.Model.registry.mappers}
    roots = [models[name] for name in TABLES]
    for model in roots:
        model.sales_workspace = db.Column(db.String(8), nullable=False, default='school', server_default='school', index=True)
    svc.SalesSchool.industry = db.Column(db.String(100), nullable=True)
    svc.SalesSchool.sponsorship_value = db.Column(db.Numeric(12, 2), nullable=True)

    @app.before_request
    def validate_sales_area():
        # School directory, school commission formulas and partner-sheet layers
        # have no business equivalent and must never be repurposed silently.
        return sales_area_error()

    @event.listens_for(db.session.session_factory, 'do_orm_execute')
    def scope_statement(state):
        area = requested_area()
        if not area or _unscoped.get() or state.execution_options.get('psa_all_sales_areas'):
            return
        # SQL criteria apply to aliases, joins, aggregates and ORM bulk DML as
        # well as lists. The value is a bound parameter (not a cached closure).
        state.statement = state.statement.options(*[
            with_loader_criteria(model, lambda record: record.sales_workspace == area, include_aliases=True)
            for model in roots
        ])

    @event.listens_for(db.session.session_factory, 'before_flush')
    def stamp_sales_area(session, _flush_context, _instances):
        for row in list(session.new):
            if type(row) not in roots or row.sales_workspace is not None:
                continue
            area = requested_area()
            # Jobs have no browser context. Derive their area from the durable
            # parent, never from a process/global preference.
            for field in ('sales_school_id', 'school_id'):
                sid = getattr(row, field, None)
                if sid:
                    parent = session.get(svc.SalesSchool, sid)
                    if parent:
                        area = parent.sales_workspace
            row.sales_workspace = area or 'school'
            if isinstance(row, svc.SalesSchool) and row.sales_workspace == 'business':
                row.school_type = 'business'

    @app.get('/api/sales-workspaces')
    def sales_areas():
        return jsonify(default='school', workspaces=[
            dict(id='school', label='School Sales', record_label='School'),
            dict(id='business', label='Business Sales', record_label='Business'),
        ])
