import json
import smtplib
from datetime import datetime, timedelta
from unittest.mock import patch
from email import message_from_string

from api.tests.test_outreach_batches import OutreachBase
from api import api as svc, outreach
from api.mail_feedback import reply_signal


class ContactOutreachTests(OutreachBase):
    def payload(self, *schools, **changes):
        return dict(school_ids=[school.id for school in schools], kind='custom', contact_mode=True,
                    audience='all', campaign_id='standard', contact_contexts={}, subject='For [school_name]',
                    body='Hello [contact_name], from [user_name]', attachment_ids=[], **changes)

    def preview(self, payload, user=None):
        response = self.client.post('/api/email-preview', headers=self.auth(user or self.owner), json=payload)
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()

    def send(self, payload, review=None, user=None):
        return self.client.post('/api/outreach/batches', headers=self.auth(user or self.owner),
                                json={**payload, **({'preview_token': review['preview_token']} if review else {})})

    def link(self, school, address, name, roles=('pta_pto',), tags=()):
        contact = svc.Contact.query.filter_by(email=address).first()
        if not contact:
            contact = svc.Contact(email=address)
            svc.db.session.add(contact); svc.db.session.flush()
        link = svc.SchoolContact.query.filter_by(school_id=school.id, contact_id=contact.id).first()
        if not link:
            link = svc.SchoolContact(school_id=school.id, contact_id=contact.id)
            svc.db.session.add(link)
        link.name, link.roles_json, link.tags_json = name, json.dumps(list(roles)), json.dumps(list(tags))
        svc.db.session.commit()
        return link, contact

    def test_resolves_all_matching_mailboxes_not_just_primary_and_no_cc(self):
        school = self.school('Contact School')
        self.link(school, 'pta@example.test', 'Sam')
        self.link(school, 'enrich@example.test', 'Jess', roles=('enrichment',))
        payload = self.payload(school)
        data = self.preview(payload)
        self.assertEqual(len(data['previews']), 3)
        self.assertEqual(self.send(payload, data).status_code, 202)
        self.run_workers()
        self.assertEqual(set(self.fake.sent), {school.email, 'pta@example.test', 'enrich@example.test'})
        self.assertTrue(all(not message.get('Cc') and not message.get('Bcc') for message in self.fake.messages))
        self.assertEqual(svc.ContactOutreachLedger.query.count(), 3)

    def test_audience_and_trunk_tag_are_distinct_from_role(self):
        school = self.school('Audience School')
        self.link(school, 'pta@example.test', 'Sam')
        self.link(school, 'enrich@example.test', 'Jess', roles=('enrichment',), tags=('trunk_or_treat',))
        payload = self.payload(school); payload['audience'] = 'pta_pto'
        self.assertEqual([r['email'] for r in self.preview(payload)['previews']], ['pta@example.test'])
        payload['audience'] = 'trunk_or_treat'
        self.assertEqual([r['email'] for r in self.preview(payload)['previews']], ['enrich@example.test'])

    def test_school_selection_does_not_hide_a_valid_contact_when_primary_is_suppressed(self):
        school = self.school('Has Another Contact', status='contacted')
        self.link(school, 'pta@example.test', 'Sam PTA')
        primary = svc.Contact.query.filter_by(email=school.email).one()
        primary.do_not_contact = True; svc.db.session.commit()
        response = self.client.get('/api/outreach/recipients?contact_mode=1&kind=initial&q=Sam', headers=self.auth(self.owner))
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertTrue(response.get_json()['items'][0]['eligible'])
        self.assertEqual(response.get_json()['items'][0]['contact_count'], 2)
        self.assertEqual(self.client.get('/api/outreach/recipients?contact_mode=1&per_page=x', headers=self.auth(self.owner)).status_code, 400)
        self.assertEqual(self.client.get('/api/outreach/recipients?contact_mode=1', headers=self.auth(self.other)).get_json()['items'], [])

    def test_followup_max_age_is_enforced_in_preview_and_worker(self):
        school = self.school('Old Conversation')
        original = self.sent_email(school, 100)
        self.sync_ready(self.owner)
        payload = self.payload(school); payload['kind'] = 'followup'
        self.assertIn('not_due', self.preview(payload)['previews'][0]['blockers'])
        self.assertEqual(self.send(payload, self.preview(payload)).status_code, 400)

    def test_distinct_campaign_can_recontact_after_reviewed_school_reset_and_cooldown(self):
        school = self.school('New Season', status='pending')
        self.sent_email(school, 100, responded=True)
        self.assertFalse(self.preview(self.payload(school))['previews'][0]['eligible'])
        campaign = self.client.post('/api/outreach/campaigns', headers=self.auth(self.admin),
            json=dict(name='Spring reopening', reason='Reviewed new-season recontact after old conversation', daily_limit=10)).get_json()
        payload = self.payload(school); payload['campaign_id'] = campaign['id']
        review = self.preview(payload)
        self.assertTrue(review['previews'][0]['eligible'])
        self.assertEqual(self.send(payload, review).status_code, 202)
        self.run_workers()
        self.assertEqual(self.fake.sent, [school.email])

    def test_shared_pta_requires_school_context_and_sends_once(self):
        left, right = self.school('Left'), self.school('Right')
        _, contact = self.link(left, 'shared@example.test', 'Left PTA')
        self.link(right, 'shared@example.test', 'Right PTA')
        payload = self.payload(left, right); payload['audience'] = 'pta_pto'
        review = self.preview(payload)
        self.assertEqual(len(review['previews']), 1)
        self.assertTrue(review['previews'][0]['context_required'])
        self.assertEqual(self.send(payload, review).status_code, 400)
        payload['contact_contexts'] = {str(contact.id): right.id}
        review = self.preview(payload)
        self.assertIn('Right PTA', review['previews'][0]['body_text'])
        self.assertEqual(self.send(payload, review).status_code, 202)
        self.run_workers()
        self.assertEqual(self.fake.sent, ['shared@example.test'])
        self.assertEqual(svc.SentEmail.query.one().sales_school_id, right.id)

    def test_cross_rep_overlap_and_replayed_review_are_not_duplicate_sends(self):
        left, right = self.school('Left'), self.school('Right', owner=self.other)
        self.link(left, 'shared@example.test', 'Sam'); self.link(right, 'shared@example.test', 'Sam')
        payload = self.payload(left); payload['audience'] = 'pta_pto'
        other = self.payload(right); other['audience'] = 'pta_pto'
        a, b = self.preview(payload), self.preview(other, self.other)
        first = self.send(payload, a)
        self.assertEqual(first.status_code, 202)
        repeat = self.send(payload, a)
        self.assertEqual((repeat.status_code, repeat.get_json()['batch_id']), (200, first.get_json()['batch_id']))
        self.assertEqual(self.send(other, b, self.other).status_code, 409)
        self.assertEqual(svc.ContactOutreachLedger.query.count(), 1)

    def test_review_is_actor_bound_expiring_and_exact(self):
        school = self.school('Review School')
        payload = self.payload(school); review = self.preview(payload)
        self.assertEqual(self.send(payload).status_code, 409)
        self.assertEqual(self.send(payload, review, self.other).status_code, 409)
        self.assertEqual(self.send({**payload, 'body': 'Changed'}, review).status_code, 409)
        row = svc.db.session.get(svc.ContactOutreachReview, review['preview_token'])
        row.expires_at = svc.utc_now() - timedelta(seconds=1); svc.db.session.commit()
        self.assertEqual(self.send(payload, review).status_code, 409)
        self.assertEqual(self.started, [])

    def test_standard_campaign_matches_legacy_mailbox_casing_and_whitespace(self):
        school = self.school('Legacy Case', email='office@example.test')
        record = self.sent_email(school, 100)
        record.school_email = ' Office@Example.test '
        svc.db.session.commit()
        preview = self.preview(self.payload(school))
        self.assertIn('campaign_already_contacted', preview['previews'][0]['blockers'])

    def test_contact_changes_invalidate_review_and_queued_message(self):
        school = self.school('Contact Edit'); payload = self.payload(school)
        review = self.preview(payload)
        link = svc.SchoolContact.query.filter_by(school_id=school.id).one()
        link.name, link.version = 'New Name', link.version + 1; svc.db.session.commit()
        self.assertEqual(self.send(payload, review).status_code, 409)
        review = self.preview(payload); self.assertEqual(self.send(payload, review).status_code, 202)
        link.version += 1; svc.db.session.commit(); self.run_workers()
        self.assertEqual(self.fake.sent, [])
        self.assertEqual(outreach.OutreachRecipient.query.one().error, 'contact_changed')

    def test_test_send_is_server_addressed_idempotent_and_not_school_history(self):
        school = self.school('Sample'); payload = self.payload(school)
        preview = self.client.post('/api/outreach/test-preview', headers=self.auth(self.owner), json=payload)
        self.assertEqual(preview.status_code, 200, preview.get_json())
        self.assertEqual(preview.get_json()['email'], self.owner.email)
        self.assertEqual(self.send(payload, preview.get_json()).status_code, 409)
        body = {**payload, 'preview_token': preview.get_json()['preview_token']}
        tampered = self.client.post('/api/outreach/test-send', headers=self.auth(self.owner), json={**body, 'to_email': 'evil@example.test'})
        self.assertEqual(tampered.status_code, 409)
        first = self.client.post('/api/outreach/test-send', headers=self.auth(self.owner), json=body)
        self.assertEqual(first.status_code, 202, first.get_json())
        self.assertEqual(self.client.post('/api/outreach/test-send', headers=self.auth(self.owner), json=body).status_code, 200)
        self.run_workers()
        self.assertEqual(self.fake.sent, [self.owner.email])
        self.assertEqual(svc.SentEmail.query.count(), 0)
        self.assertEqual(svc.SentMessage.query.count(), 0)
        self.assertEqual(svc.ContactOutreachLedger.query.count(), 0)
        self.assertEqual(svc.db.session.get(svc.SalesSchool, school.id).status, 'pending')
        self.assertEqual(outreach.limits_for(self.owner)['sent_today'], 1)

    def test_hard_bounce_pauses_after_first_detected_failure(self):
        schools = [self.school('Bounce ' + str(i)) for i in range(4)]
        payload = self.payload(*schools); review = self.preview(payload)
        result = self.send(payload, review); self.assertEqual(result.status_code, 202)
        self.fake.send_message = lambda *args: (_ for _ in ()).throw(smtplib.SMTPDataError(550, b'5.1.1 No such user'))
        self.run_workers()
        batch = outreach.OutreachBatch.query.one()
        self.assertEqual(batch.status, 'paused')
        self.assertEqual(outreach.OutreachRecipient.query.filter_by(status='queued').count(), 3)
        self.assertTrue(svc.Contact.query.filter_by(email=schools[0].email).one().do_not_contact)
        self.assertEqual(svc.MailContactSignal.query.count(), 1)

    def test_stop_request_cancels_matching_contact_and_pauses_remaining(self):
        schools = [self.school('Stop ' + str(i)) for i in range(3)]
        payload = self.payload(*schools); self.send(payload, self.preview(payload))
        svc.record_mail_signal(schools[0].email, 'optout', 'test:stop', 'Please remove me', actor_id=self.owner.id)
        svc.db.session.commit(); self.run_workers()
        self.assertEqual(self.fake.sent, [])
        self.assertEqual(outreach.OutreachBatch.query.one().status, 'paused')
        self.assertEqual(svc.db.session.get(svc.SalesSchool, schools[0].id).status, 'not_interested')
        self.assertFalse(svc.record_mail_signal(schools[0].email, 'optout', 'test:stop', 'Duplicate'))

    def test_manual_signals_require_contact_access_and_source_details(self):
        school = self.school('Report')
        contact = svc.Contact.query.filter_by(email=school.email).one()
        path = f'/api/contacts/{contact.id}/report'
        payload = dict(kind='complaint', detail='Recipient called and reported unwanted outreach')
        self.assertEqual(self.client.post(path, json=payload).status_code, 401)
        self.assertEqual(self.client.post(path, headers=self.auth(self.other), json=payload).status_code, 404)
        self.assertEqual(self.client.post(path, headers=self.auth(self.owner), json={'kind': 'complaint'}).status_code, 400)
        self.assertEqual(self.client.post(path, headers=self.auth(self.owner), json=payload).status_code, 200)
        self.assertTrue(svc.contact_is_blocked(school.email))
        self.assertEqual(svc.MailContactSignal.query.one().actor_id, self.owner.id)

    def test_chunk_checks_inbox_and_pauses_if_backlog_or_outage(self):
        schools = [self.school('Chunk ' + str(i)) for i in range(8)]
        payload = self.payload(*schools); self.send(payload, self.preview(payload))
        with patch.object(svc, 'sync_user_mailbox', return_value={'ready': False}): self.run_workers()
        self.assertEqual(len(self.fake.sent), 5)
        self.assertEqual(outreach.OutreachBatch.query.one().status, 'paused')
        self.assertEqual(outreach.OutreachRecipient.query.filter_by(status='queued').count(), 3)

    def test_campaign_creation_is_admin_only_and_recontact_explicit(self):
        body = dict(name='New season', reason='New approved seasonal program', daily_limit=2)
        self.assertEqual(self.client.post('/api/outreach/campaigns', headers=self.auth(self.owner), json=body).status_code, 403)
        response = self.client.post('/api/outreach/campaigns', headers=self.auth(self.admin), json=body)
        self.assertEqual(response.status_code, 201)
        schools = [self.school('Cap ' + str(i)) for i in range(3)]
        payload = self.payload(*schools); payload['campaign_id'] = response.get_json()['id']
        self.assertEqual(self.send(payload, self.preview(payload)).status_code, 429)
        self.assertEqual(self.started, [])

    def test_followups_use_the_campaign_conversation_and_one_ledger_entry_per_step(self):
        school = self.school('Sequence')
        payload = self.payload(school)
        self.send(payload, self.preview(payload)); self.run_workers()
        original = svc.SentEmail.query.one()
        original.sent_at = svc.utc_now() - timedelta(days=8)
        for message in svc.SentMessage.query.all(): message.sent_at = original.sent_at
        svc.db.session.commit(); self.sync_ready(self.owner)
        payload['kind'] = 'followup'
        first = self.preview(payload)
        self.assertEqual(self.send(payload, first).status_code, 202)
        self.run_workers()
        self.assertEqual(svc.SentEmail.query.one().followup_count, 1)
        self.assertEqual(svc.ContactOutreachLedger.query.count(), 2)
        second = self.preview(payload)
        self.assertEqual(second['previews'][0]['step'], 'followup-2')
        self.assertEqual(self.send(payload, second).status_code, 202)
        self.run_workers()
        self.assertEqual(svc.SentEmail.query.one().followup_count, 2)
        self.assertEqual(svc.ContactOutreachLedger.query.count(), 3)
        self.assertEqual(self.send(payload, self.preview(payload)).status_code, 400)

    def test_unconfirmed_attempt_still_consumes_quota_after_reviewed_resend(self):
        school = self.school('Uncertain')
        self.fake.disconnect_once_for = {school.email}
        payload = self.payload(school)
        result = self.send(payload, self.preview(payload)); self.run_workers()
        bid = result.get_json()['batch_id']
        self.assertEqual(outreach.sent_today(self.owner.id), 1)
        self.assertEqual(self.reviewed_retry(bid, include=True).status_code, 202)
        self.run_workers()
        self.assertEqual(self.fake.sent, [school.email])
        self.assertEqual(outreach.sent_today(self.owner.id), 2)
        self.assertEqual(outreach.OutreachAttempt.query.filter_by(status='unconfirmed').count(), 1)
        history = self.get_batch(self.owner, bid)['recipients'][0]['attempts']
        self.assertEqual([attempt['status'] for attempt in history], ['unconfirmed', 'sent'])

    def test_inbox_signal_during_chunk_refresh_stops_before_next_send(self):
        schools = [self.school('Signal ' + str(i)) for i in range(8)]
        payload = self.payload(*schools); self.send(payload, self.preview(payload))
        def refresh(user):
            svc.record_mail_signal(schools[0].email, 'optout', 'test:chunk-stop', 'Please stop', actor_id=user.id)
            svc.db.session.commit()
            return {'ready': True}
        with patch.object(svc, 'sync_user_mailbox', side_effect=refresh): self.run_workers()
        self.assertEqual(len(self.fake.sent), 5)
        self.assertEqual(outreach.OutreachBatch.query.one().status, 'paused')

    def test_resend_requires_fresh_review_and_only_original_sender(self):
        school = self.school('Retry')
        self.fake.fail_for = {school.email}
        payload = self.payload(school); result = self.send(payload, self.preview(payload)); self.run_workers()
        bid = result.get_json()['batch_id']
        path = f'/api/outreach/batches/{bid}/retry'
        self.assertEqual(self.client.post(path, headers=self.auth(self.owner), json={}).status_code, 409)
        self.assertEqual(self.client.post(path, headers=self.auth(self.admin), json={}).status_code, 403)
        self.fake.fail_for.clear()
        self.assertEqual(self.reviewed_retry(bid).status_code, 202)
        self.run_workers()
        self.assertEqual(self.fake.sent, [school.email])

    def test_platform_and_mailbox_caps_use_the_lower_value(self):
        with patch.dict('os.environ', {'OUTREACH_DAILY_LIMIT': '150', 'OUTREACH_MAILBOX_DAILY_LIMIT': '2'}):
            self.assertEqual(outreach.limits_for(self.owner)['daily_limit'], 2)
            schools = [self.school('Mailbox Cap ' + str(i)) for i in range(3)]
            payload = self.payload(*schools)
            self.assertEqual(self.send(payload, self.preview(payload)).status_code, 429)

    def test_quota_day_is_eastern_and_handles_both_dst_transitions(self):
        for date, hours in [(datetime(2026, 3, 8, 14), 23), (datetime(2026, 11, 1, 14), 25)]:
            with patch.object(svc, 'utc_now', return_value=date):
                start, end = outreach.day_bounds()
                self.assertEqual((end-start).total_seconds()/3600, hours)
        with patch.object(svc, 'utc_now', return_value=datetime(2026, 11, 5, 2)):
            self.assertEqual(outreach.day_start(), datetime(2026, 11, 4, 5))

    def test_old_http_send_paths_cannot_bypass_review_or_quota(self):
        for path in ('send-email', 'send-followup', 'send-custom-email', 'send-custom-email-bulk', 'send-custom-reply', 'crm/outreach/send'):
            self.assertEqual(self.client.post('/api/' + path).status_code, 401)
            result = self.client.post('/api/' + path, headers=self.auth(self.owner), json={})
            self.assertEqual(result.status_code, 409)
        self.assertEqual(self.fake.sent, [])

    def test_reply_is_reviewed_to_original_contact_and_counts_quota(self):
        school = self.school('Answered', status='replied')
        record = self.sent_email(school, 10, responded=True)
        svc.db.session.add(svc.SentMessage(sent_email_id=record.id, message_id='<original@test>', kind='outreach', subject='Hello'))
        svc.db.session.commit()
        payload = dict(email_id=record.id, subject='Re: Hello', message='Thanks for your reply')
        review = self.client.post('/api/outreach/reply-preview', headers=self.auth(self.owner), json=payload)
        self.assertEqual(review.status_code, 200, review.get_json())
        response = self.client.post('/api/outreach/reply-send', headers=self.auth(self.owner), json={**payload, 'preview_token': review.get_json()['preview_token']})
        self.assertEqual(response.status_code, 202, response.get_json())
        self.run_workers()
        self.assertEqual(self.fake.sent, [school.email])
        self.assertEqual(self.fake.messages[0]['In-Reply-To'], '<original@test>')
        self.assertEqual(svc.SentMessage.query.filter_by(kind='reply').count(), 1)
        self.assertEqual(svc.SentEmail.query.count(), 1)
        self.assertEqual(svc.db.session.get(svc.SalesSchool, school.id).status, 'replied')

    def test_reply_classifier_ignores_quoted_footer_and_flags_ambiguous(self):
        self.assertIsNone(reply_signal('Sounds great\nOn Tue someone wrote:\nUnsubscribe'))
        self.assertEqual(reply_signal('Please remove us from your list'), 'optout')
        self.assertEqual(reply_signal('Not interested this season'), 'review')

    def test_delivery_report_requires_original_message_and_exact_failed_mailbox(self):
        school = self.school('DSN'); sent = self.sent_email(school, 1)
        def report(address):
            return message_from_string('MIME-Version: 1.0\nContent-Type: multipart/report; report-type=delivery-status; boundary="dsn"\n\n'
                '--dsn\nContent-Type: message/delivery-status\n\nReporting-MTA: dns; example.test\n\n'
                f'Final-Recipient: rfc822; {address}\nAction: failed\nStatus: 5.1.1\n\n'
                '--dsn\nContent-Type: message/rfc822\n\nMessage-ID: <original@test>\n\nOriginal\n--dsn--\n')
        self.assertFalse(svc.process_delivery_report(report('other@example.test'), {'<original@test>': sent}, self.owner.id))
        self.assertTrue(svc.process_delivery_report(report(school.email), {'<original@test>': sent}, self.owner.id))
        svc.db.session.commit()
        self.assertTrue(svc.contact_is_blocked(school.email))
