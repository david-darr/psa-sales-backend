"""Credential encryption and the admin migration without real mail traffic."""

import base64
import os
import unittest
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET_KEY"] = "local-test-key"
os.environ.setdefault("MAIL_CREDENTIAL_KEY", base64.urlsafe_b64encode(b"0" * 32).decode())

from api import api as service  # noqa: E402


class MailCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        service.app.config["TESTING"] = True
        cls.context = service.app.app_context()
        cls.context.push()
        service.db.create_all()
        cls.client = service.app.test_client()
        cls.admin = service.User(name="Admin", email="admin@example.com", admin=True)
        cls.admin.set_password("test-password")
        cls.staff = service.User(name="Staff", email="staff@example.com", admin=False)
        cls.staff.set_password("test-password")
        service.db.session.add_all([cls.admin, cls.staff])
        service.db.session.commit()
        cls.school = service.SalesSchool(
            school_name="Test School", email="school@example.com",
            school_type="preschool", user_id=cls.staff.id,
        )
        service.db.session.add(cls.school)
        service.db.session.commit()
        cls.admin_token = service.create_access_token(identity=str(cls.admin.id))
        cls.staff_token = service.create_access_token(identity=str(cls.staff.id))

    @classmethod
    def tearDownClass(cls):
        service.db.session.remove()
        service.db.drop_all()
        service.db.engine.dispose()
        cls.context.pop()

    def setUp(self):
        self.admin.email_password = None
        self.staff.email_password = None
        service.db.session.commit()

    def auth(self, admin=False):
        token = self.admin_token if admin else self.staff_token
        return {"Authorization": f"Bearer {token}"}

    def test_save_encrypts_and_smtp_receives_only_decrypted_value(self):
        secret = "test-app-password"
        response = self.client.post(
            "/api/email-settings", json={"email_password": secret}, headers=self.auth()
        )
        self.assertEqual(response.status_code, 200)
        service.db.session.refresh(self.staff)
        stored = self.staff.email_password
        self.assertTrue(service.is_encrypted(stored))
        self.assertNotIn(secret, stored)
        self.assertEqual(service.user_mail_password(self.staff), secret)

        with patch.object(service, "send_emails_over_connection", return_value=[]) as send:
            self.client.post(
                "/api/send-email", json={"school_ids": [self.school.id]}, headers=self.auth()
            )
        self.assertEqual(send.call_args.args[1], secret)

    def test_imap_receives_decrypted_value(self):
        self.staff.email_password = service.encrypt_password("imap-test-password")
        service.db.session.commit()
        with patch.object(service.imaplib, "IMAP4_SSL") as imap:
            imap.return_value.search.return_value = ("OK", [b""])
            self.assertEqual(service.check_user_email_replies_limited(self.staff), 0)
            imap.return_value.login.assert_called_once_with(
                self.staff.email, "imap-test-password"
            )

    def test_admin_migration_is_idempotent_and_staff_cannot_run_it(self):
        self.staff.email_password = "legacy-test-password"
        service.db.session.commit()
        path = "/api/mail-credential-migration"
        self.assertEqual(self.client.get(path).status_code, 401)
        self.assertEqual(self.client.get(path, headers=self.auth()).status_code, 403)
        self.assertEqual(
            self.client.post(
                path, json={"confirm": "ENCRYPT_EXISTING_MAIL_PASSWORDS"},
                headers=self.auth(),
            ).status_code,
            403,
        )
        before = self.client.get(path, headers=self.auth(admin=True)).get_json()
        self.assertEqual((before["configured"], before["legacy"]), (1, 1))
        self.assertNotIn("legacy-test-password", str(before))
        self.assertEqual(
            self.client.post(path, json={}, headers=self.auth(admin=True)).status_code,
            400,
        )

        first = self.client.post(
            path, json={"confirm": "ENCRYPT_EXISTING_MAIL_PASSWORDS"},
            headers=self.auth(admin=True),
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.get_json()["migrated"], 1)
        self.assertEqual(first.get_json()["legacy"], 0)
        self.assertTrue(service.is_encrypted(self.staff.email_password))
        with patch.dict(os.environ, {"MAIL_CREDENTIAL_ALLOW_LEGACY": "false"}):
            self.assertEqual(service.user_mail_password(self.staff), "legacy-test-password")

        second = self.client.post(
            path, json={"confirm": "ENCRYPT_EXISTING_MAIL_PASSWORDS"},
            headers=self.auth(admin=True),
        )
        self.assertEqual(second.get_json()["migrated"], 0)

    def test_strict_mode_rejects_plaintext_and_bad_tokens(self):
        self.staff.email_password = "legacy-test-password"
        service.db.session.commit()
        with patch.dict(os.environ, {"MAIL_CREDENTIAL_ALLOW_LEGACY": "true"}):
            self.assertEqual(service.user_mail_password(self.staff), "legacy-test-password")
        with patch.dict(os.environ, {"MAIL_CREDENTIAL_ALLOW_LEGACY": "false"}):
            with self.assertRaises(service.MailCredentialUnavailable):
                service.user_mail_password(self.staff)
            result = self.client.post(
                "/api/send-email", json={"school_ids": [self.school.id]}, headers=self.auth()
            )
            self.assertEqual(result.status_code, 503)
            self.assertNotIn("legacy-test-password", result.get_data(as_text=True))

        self.staff.email_password = "fernet:v1:invalid-token"
        service.db.session.commit()
        with self.assertRaises(service.MailCredentialUnavailable):
            service.user_mail_password(self.staff)

    def test_corrupt_token_blocks_migration_without_partial_changes(self):
        self.staff.email_password = "legacy-test-password"
        self.admin.email_password = "fernet:v1:invalid-token"
        service.db.session.commit()
        path = "/api/mail-credential-migration"
        before = self.client.get(path, headers=self.auth(admin=True)).get_json()
        self.assertEqual(before["legacy"], 1)
        self.assertEqual(before["invalid"], 1)

        result = self.client.post(
            path, json={"confirm": "ENCRYPT_EXISTING_MAIL_PASSWORDS"},
            headers=self.auth(admin=True),
        )
        self.assertEqual(result.status_code, 503)
        service.db.session.refresh(self.staff)
        self.assertEqual(self.staff.email_password, "legacy-test-password")


if __name__ == "__main__":
    unittest.main()
