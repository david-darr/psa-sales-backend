"""Follow-up eligibility, preview, and send permissions."""

import os
import base64
import unittest
from datetime import timedelta
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET_KEY"] = "local-test-key"
os.environ.setdefault("MAIL_CREDENTIAL_KEY", base64.urlsafe_b64encode(b"0" * 32).decode())

from api import api as service  # noqa: E402


class FollowupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        service.app.config["TESTING"] = True
        cls.context = service.app.app_context()
        cls.context.push()
        service.db.create_all()
        cls.client = service.app.test_client()

        cls.owner = service.User(name="Owner", email="owner@example.com", admin=False)
        cls.owner.set_password("test-password")
        cls.owner.email_password = service.encrypt_password("test-app-password")
        cls.other = service.User(name="Other", email="other@example.com", admin=False)
        cls.other.set_password("test-password")
        cls.other.email_password = service.encrypt_password("test-app-password")
        cls.admin = service.User(name="Admin", email="admin@example.com", admin=True)
        cls.admin.set_password("test-password")
        cls.admin.email_password = service.encrypt_password("test-app-password")
        service.db.session.add_all([cls.owner, cls.other, cls.admin])
        service.db.session.commit()
        cls.tokens = {
            user.id: service.create_access_token(identity=str(user.id))
            for user in (cls.owner, cls.other, cls.admin)
        }

        cls.school = service.SalesSchool(
            school_name="Cedar Grove", email="main@example.com", school_type="preschool",
            user_id=cls.owner.id,
        )
        cls.school.set_additional_emails(["director@example.com"])
        service.db.session.add(cls.school)
        service.db.session.commit()

    @classmethod
    def tearDownClass(cls):
        service.db.session.remove()
        service.db.drop_all()
        service.db.engine.dispose()
        cls.context.pop()

    def setUp(self):
        self.records = []

    def tearDown(self):
        for record in self.records:
            service.db.session.delete(record)
        service.db.session.commit()

    def auth(self, user):
        return {"Authorization": f"Bearer {self.tokens[user.id]}"}

    def email(self, age_days=8, **fields):
        values = {
            "school_name": "Cedar Grove",
            "school_email": "director@example.com",
            "sent_at": service.utc_now() - timedelta(days=age_days),
            "responded": False,
            "followup_sent": False,
            "user_id": self.owner.id,
        }
        values.update(fields)
        record = service.SentEmail(**values)
        service.db.session.add(record)
        service.db.session.commit()
        self.records.append(record)
        return record

    def test_preview_matches_message_sent_and_secondary_contact_template(self):
        record = self.email()
        preview = self.client.get(
            f"/api/followup-preview/{record.id}", headers=self.auth(self.owner)
        )
        self.assertEqual(preview.status_code, 200)
        body = preview.get_json()
        self.assertEqual(body["to_email"], "director@example.com")
        self.assertIn("preschool sports programs", body["body"])
        self.assertEqual(body["subject"], service.FOLLOWUP_SUBJECT)

        with patch.object(service, "send_email_with_attachments", return_value=True) as send:
            result = self.client.post(
                "/api/send-followup", json={"email_id": record.id}, headers=self.auth(self.owner)
            )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(send.call_args.kwargs["body"], body["body"])
        self.assertEqual(send.call_args.kwargs["from_password"], "test-app-password")
        self.assertTrue(record.followup_sent)
        self.assertEqual(
            self.client.post(
                "/api/send-followup", json={"email_id": record.id}, headers=self.auth(self.owner)
            ).status_code,
            409,
        )

    def test_recent_responded_and_sent_records_never_send(self):
        records = [
            self.email(age_days=6),
            self.email(responded=True),
            self.email(followup_sent=True),
        ]
        with patch.object(service, "send_email_with_attachments") as send:
            for record in records:
                with self.subTest(record=record.id):
                    preview = self.client.get(
                        f"/api/followup-preview/{record.id}", headers=self.auth(self.owner)
                    )
                    result = self.client.post(
                        "/api/send-followup", json={"email_id": record.id},
                        headers=self.auth(self.owner),
                    )
                    self.assertEqual(preview.status_code, 409)
                    self.assertEqual(result.status_code, 409)
            send.assert_not_called()

    def test_seven_day_boundary_and_failed_smtp(self):
        now = service.utc_now()
        record = self.email(sent_at=now - timedelta(days=7))
        with patch.object(service, "utc_now", return_value=now):
            self.assertIsNone(service.followup_eligibility_error(record))
            record.sent_at = now - timedelta(days=7) + timedelta(seconds=1)
            self.assertIsNotNone(service.followup_eligibility_error(record))

        record.sent_at = now - timedelta(days=8)
        service.db.session.commit()
        with patch.object(service, "send_email_with_attachments", return_value=False):
            result = self.client.post(
                "/api/send-followup", json={"email_id": record.id}, headers=self.auth(self.owner)
            )
        self.assertEqual(result.status_code, 500)
        self.assertFalse(record.followup_sent)

    def test_queue_and_preview_only_expose_owned_due_email(self):
        due = self.email()
        recent = self.email(age_days=2)
        self.assertEqual(
            self.client.get(f"/api/followup-preview/{due.id}").status_code, 401
        )
        self.assertEqual(
            self.client.get(
                f"/api/followup-preview/{due.id}", headers=self.auth(self.other)
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                "/api/send-followup", json={"email_id": due.id}, headers=self.auth(self.admin)
            ).status_code,
            404,
        )

        owner_rows = self.client.get("/api/sent-emails", headers=self.auth(self.owner)).get_json()
        self.assertTrue(next(row for row in owner_rows if row["id"] == due.id)["followup_eligible"])
        self.assertFalse(next(row for row in owner_rows if row["id"] == recent.id)["followup_eligible"])
        admin_rows = self.client.get("/api/sent-emails", headers=self.auth(self.admin)).get_json()
        self.assertFalse(next(row for row in admin_rows if row["id"] == due.id)["followup_eligible"])

    def test_profile_reports_connection_status_without_credential(self):
        profile = self.client.get("/api/profile", headers=self.auth(self.owner)).get_json()
        self.assertTrue(profile["mail_connected"])
        self.assertNotIn("email_password", profile)


if __name__ == "__main__":
    unittest.main()
