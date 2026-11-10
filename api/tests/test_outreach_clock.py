import hashlib
from datetime import timedelta
from unittest.mock import Mock,patch
from api.tests.test_outreach_batches import OutreachBase, service
from api.mail_jobs import sync_mailboxes


class ClockTests(OutreachBase):
    def setUp(self):
        super().setUp()
        self.token='a'*64
        service.db.session.add(service.OutreachClockCredential(id=1,
            token_hash=hashlib.sha256(self.token.encode()).hexdigest()))
        service.db.session.commit()

    def wake(self,token=None,**body):
        return self.client.post('/api/internal/outreach/wake',headers={'Authorization':'Bearer '+(token or self.token)},json=body)

    def test_bad_tokens_and_employee_jwt_cannot_wake_scheduler(self):
        for token in ('bad','b'*64,service.create_access_token(identity=str(self.owner.id))):
            self.assertEqual(self.wake(token).status_code,401)

    def test_credential_only_wakes_worker_and_is_rate_limited(self):
        worker=Mock()
        with patch.dict(service.app.extensions,{'psa_web_outreach_worker':worker}):
            first=self.wake(to='untrusted@example.test',approve=True)
            self.assertEqual(first.status_code,202)
            self.assertTrue(first.get_json()['accepted'])
            self.assertFalse(self.wake().get_json()['accepted'])
            worker.start.assert_called_once_with()
            self.assertEqual(service.SentEmail.query.count(),0)
        self.assertNotIn(self.token,str(first.get_json()))

    def test_missing_web_worker_fails_without_claiming_wake(self):
        self.assertEqual(self.wake().status_code,503)
        self.assertIsNone(service.db.session.get(service.OutreachClockCredential,1).last_wake_at)

    def test_reply_turn_skips_fresh_mailboxes_and_resumes_unfinished_scan(self):
        school=self.school('Clock school');self.sent_email(school,1)
        self.sync_ready(self.owner)
        with patch.object(service,'sync_user_mailbox',return_value={'replies_found':0,'pending_count':0}) as sync:
            self.assertEqual(sync_mailboxes(service,max_batches=1,stale_only=True)['batches'],0)
            state=service.db.session.get(service.MailSyncState,self.owner.id)
            state.pending_count=10;service.db.session.commit()
            self.assertEqual(sync_mailboxes(service,max_batches=1,stale_only=True)['batches'],1)
            self.assertEqual(sync.call_count,1)
            state.last_error='Provider unavailable';service.db.session.commit()
            self.assertEqual(sync_mailboxes(service,max_batches=1,stale_only=True)['batches'],0)
            state.last_checked_at=service.utc_now()-timedelta(minutes=31);service.db.session.commit()
            self.assertEqual(sync_mailboxes(service,max_batches=1,stale_only=True)['batches'],1)
