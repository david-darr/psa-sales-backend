"""Narrow authenticated wake-up for existing-compute queue processing.

The scheduler credential can only wake the worker, never approve, address or
alter mail. Hash only in the application table; secret lives in Supabase Vault.
"""
import hashlib
import hmac
from datetime import timedelta

from flask import jsonify, request
from sqlalchemy import update, or_


def register_outreach_clock(app,db,svc):
    class Credential(db.Model):
        __tablename__='outreach_clock_credentials'
        id=db.Column(db.Integer,primary_key=True)
        token_hash=db.Column(db.String(64),nullable=False)
        last_wake_at=db.Column(db.DateTime)

    svc.OutreachClockCredential=Credential

    @app.post('/api/internal/outreach/wake')
    def wake():
        auth=request.headers.get('Authorization','')
        token=auth[7:] if auth.startswith('Bearer ') else ''
        if len(token)!=64 or any(c not in '0123456789abcdef' for c in token):
            return jsonify(error='Invalid scheduler credential'),401
        row=db.session.get(Credential,1)
        actual=hashlib.sha256(token.encode()).hexdigest()
        if row is None or not hmac.compare_digest(actual,row.token_hash):
            return jsonify(error='Invalid scheduler credential'),401
        worker=app.extensions.get('psa_web_outreach_worker')
        if worker is None:
            return jsonify(error='Web worker mode is not configured'),503
        moment=svc.utc_now()
        claimed=db.session.execute(update(Credential).where(Credential.id==1,
            or_(Credential.last_wake_at.is_(None),Credential.last_wake_at<=moment-timedelta(minutes=1))
            ).values(last_wake_at=moment)).rowcount
        db.session.commit()
        if claimed:worker.start()
        return jsonify(accepted=bool(claimed)),202

    return Credential
