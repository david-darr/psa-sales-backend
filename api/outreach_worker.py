"""Dedicated durable outreach process. Importing this module never starts it.

python -m api.outreach_worker --once
python -m api.outreach_worker --poll-seconds 10
Run only in an explicitly configured worker deployment with the app's secrets.
"""
import argparse
import os
import time
import uuid
from datetime import timedelta

from flask import jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import and_, or_, update


def register_worker(app, db, svc, out):
    class Heartbeat(db.Model):
        __tablename__ = 'outreach_worker_heartbeats'
        id = db.Column(db.String(36), primary_key=True)
        last_seen_at = db.Column(db.DateTime, nullable=False, default=out.now)
        status = db.Column(db.String(12), nullable=False, default='idle')
        last_error = db.Column(db.Text)
        batches = db.Column(db.Integer, nullable=False, default=0)

    svc.OutreachWorkerHeartbeat = Heartbeat

    @app.get('/api/outreach/worker')
    @jwt_required()
    def worker_status():
        if not out.current_user(): return jsonify(error='User not found'), 404
        latest = Heartbeat.query.order_by(Heartbeat.last_seen_at.desc()).first()
        return jsonify(online=bool(latest and not latest.last_error and latest.status != 'stopped' and latest.last_seen_at >= out.now()-timedelta(minutes=5)),
            has_error=bool(latest and latest.last_error),
            last_seen_at=out.iso(latest.last_seen_at) if latest else None,
            status=latest.status if latest else 'not_started',
            message='Queued mail waits for the separate worker. This page does not send it in a web thread.')

    def recover():
        # A checker has not begun SMTP. Its fenced lease is safe to reclaim.
        S = svc.SequenceStep
        db.session.execute(update(S).where(S.status=='checking', S.lease_until < out.now()).values(
            status='waiting', lease_token=None, lease_until=None))
        batches = out.OutreachBatch.query.filter(out.OutreachBatch.status.in_(('queued','sending')),
            or_(out.OutreachBatch.lease_until < out.now(), and_(out.OutreachBatch.status=='sending',
                out.OutreachBatch.lease_until.is_(None), out.OutreachBatch.heartbeat_at < out.now()-out.STALL_AFTER))).order_by(out.OutreachBatch.id).with_for_update(skip_locked=True).limit(20).all()
        reconcile = []
        for batch in batches:
            if out.OutreachRecipient.query.filter_by(batch_id=batch.id, status='sending').first():
                out.mark_stalled_unconfirmed(batch.id)
                batch.status, batch.paused_reason = 'paused', 'Worker lease expired during a send. Check Sent mail and review remaining messages.'
                reconcile.extend(r.id for r in out.OutreachRecipient.query.filter_by(batch_id=batch.id, status='unconfirmed'))
            else:
                batch.status = 'queued'
            batch.worker_token, batch.lease_owner, batch.lease_until = str(uuid.uuid4()), None, None
        db.session.commit()
        for recipient_id in reconcile:
            svc.sequence_result(recipient_id);db.session.commit()
        db.session.commit()

    def cycle(worker_id, max_jobs=5):
        if not 1 <= max_jobs <= 20: raise ValueError('Use a bounded work limit from 1 to 20')
        heartbeat = db.session.get(Heartbeat, worker_id)
        if not heartbeat:
            heartbeat = Heartbeat(id=worker_id); db.session.add(heartbeat)
        heartbeat.last_seen_at, heartbeat.status, heartbeat.last_error = out.now(), 'running', None
        db.session.commit()
        report = dict(scheduled=0, batches=0)
        try:
            recover()
            report['scheduled'] = svc.schedule_sequences(max_jobs)
            for _ in range(max_jobs):
                # One oldest batch per claim; leases + row locks coordinate workers.
                batch = out.OutreachBatch.query.filter(out.OutreachBatch.status=='queued',
                    out.OutreachBatch.lease_owner.is_(None),or_(out.OutreachBatch.available_at.is_(None),out.OutreachBatch.available_at<=out.now())
                    ).order_by(out.OutreachBatch.heartbeat_at, out.OutreachBatch.id).with_for_update(skip_locked=True).first()
                if not batch: db.session.rollback(); break
                batch.worker_token = str(uuid.uuid4())
                batch.lease_owner, batch.lease_until = worker_id, out.now()+timedelta(minutes=5)
                bid, token, uid, kind = batch.id, batch.worker_token, batch.user_id, batch.kind
                db.session.commit(); db.session.remove()
                if kind=='sequence':
                    allowed=svc.sequence_dispatch_time(bid)
                    if allowed and allowed>out.now():
                        db.session.execute(update(out.OutreachBatch).where(out.OutreachBatch.id==bid,out.OutreachBatch.worker_token==token).values(
                            available_at=allowed,lease_owner=None,lease_until=None))
                        db.session.commit();continue
                if kind not in ('test','reply'):
                    try: ready = svc.sync_user_mailbox(db.session.get(svc.User,uid)).get('ready',False)
                    except Exception: db.session.rollback(); ready=False
                    if not ready:
                        db.session.execute(update(out.OutreachBatch).where(out.OutreachBatch.id==bid,
                            out.OutreachBatch.worker_token==token).values(status='paused', paused_reason='Inbox check incomplete; review before continuing',
                            lease_owner=None,lease_until=None))
                        for recipient in out.OutreachRecipient.query.filter_by(batch_id=bid,status='queued'):
                            svc.pause_sequence_recipient(recipient.id,'Inbox check incomplete')
                        db.session.commit(); continue
                # Five recipients per turn: another rep isn't held behind a huge batch.
                out.run_batch(app, bid, token, max_recipients=5)
                report['batches'] += 1
                heartbeat = db.session.get(Heartbeat, worker_id)
                heartbeat.last_seen_at = out.now(); heartbeat.batches += 1
                db.session.commit()
        except Exception:
            db.session.rollback()
            heartbeat = db.session.get(Heartbeat, worker_id)
            heartbeat.last_error = 'Worker cycle failed; inspect server logs'
            svc.logging.exception('Outreach worker cycle failed')
            raise
        finally:
            heartbeat = db.session.get(Heartbeat, worker_id)
            if heartbeat:
                heartbeat.last_seen_at, heartbeat.status = out.now(), 'idle'
                db.session.commit()
            db.session.remove()
        return report

    svc.run_outreach_cycle, svc.recover_outreach_leases = cycle, recover


def main():
    parser = argparse.ArgumentParser(description='Run the PSA durable outreach worker')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--poll-seconds', type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.poll_seconds <= 60: parser.error('poll seconds must be 1–60')
    os.environ['PSA_DISABLE_SCHEDULER'] = 'true'
    from api import api as svc
    worker_id = str(uuid.uuid4())
    try:
        while True:
            try:
                with svc.app.app_context(): print(svc.run_outreach_cycle(worker_id), flush=True)
            except Exception:
                if args.once: raise
            if args.once: return
            time.sleep(args.poll_seconds)
    except KeyboardInterrupt:
        with svc.app.app_context():
            row = svc.db.session.get(svc.OutreachWorkerHeartbeat, worker_id)
            if row: row.status='stopped'; svc.db.session.commit()


if __name__ == '__main__': main()
