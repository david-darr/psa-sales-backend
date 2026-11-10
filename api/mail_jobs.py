"""Fair, resumable mailbox sweeps for a separately scheduled worker."""
import time
from collections import deque


def sync_mailboxes(service, budget_seconds=240, max_batches=200, stale_only=False):
    query = service.User.query.outerjoin(service.MailSyncState,
        service.MailSyncState.user_id == service.User.id).filter(
        service.User.email_password.isnot(None), service.User.email_password != '',
        service.User.id.in_(service.db.session.query(service.SentEmail.user_id).distinct()),
    )
    if stale_only:
        from datetime import timedelta
        query=query.filter(service.or_(service.MailSyncState.last_checked_at.is_(None),
            service.MailSyncState.last_checked_at <= service.utc_now()-timedelta(minutes=30),
            service.and_(service.MailSyncState.pending_count>0,service.MailSyncState.last_error.is_(None))))
    users=query.order_by(service.MailSyncState.last_checked_at.asc().nullsfirst(), service.User.id).all()
    queue = deque(users)
    deadline = time.monotonic() + budget_seconds
    report = {'mailboxes': 0, 'batches': 0, 'replies': 0, 'errors': 0, 'unfinished': 0}
    visited = set()
    while queue and time.monotonic() < deadline and report['batches'] < max_batches:
        user = queue.popleft()
        visited.add(user.id)
        report['batches'] += 1
        try:
            result = service.sync_user_mailbox(user)
            report['replies'] += result['replies_found']
            if result['pending_count']:
                queue.append(user)
        except Exception:
            service.db.session.rollback()
            report['errors'] += 1
            service.logging.warning('Scheduled mailbox check failed for user %s', user.id)
    report['mailboxes'] = len(visited)
    report['unfinished'] = len(queue)
    return report
