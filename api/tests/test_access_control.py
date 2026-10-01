"""Regression checks for employee invitations and protected API routes."""

import os
import unittest

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET_KEY"] = "local-test-key"

from api import api as service  # noqa: E402


class AccessControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        service.app.config["TESTING"] = True
        cls.context = service.app.app_context()
        cls.context.push()
        service.db.create_all()

        admin = service.User(name="Admin", email="admin@example.com", admin=True)
        admin.set_password("admin-password")
        staff = service.User(name="Staff", email="staff@example.com", admin=False)
        staff.set_password("staff-password")
        service.db.session.add_all([admin, staff])
        service.db.session.commit()
        cls.admin_token = service.create_access_token(identity=str(admin.id))
        cls.staff_token = service.create_access_token(identity=str(staff.id))
        cls.client = service.app.test_client()

    @classmethod
    def tearDownClass(cls):
        service.db.session.remove()
        service.db.drop_all()
        service.db.engine.dispose()
        cls.context.pop()

    def auth(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_operational_routes_reject_anonymous_requests(self):
        for path, method in (
            ("/api/schools", "get"),
            ("/api/map-schools", "get"),
            ("/api/find-schools", "post"),
            ("/api/route-plan", "post"),
            ("/api/refresh-map-schools", "post"),
            ("/api/all-schools", "get"),
            ("/api/all-emails", "get"),
        ):
            with self.subTest(path=path):
                response = getattr(self.client, method)(path, json={})
                self.assertEqual(response.status_code, 401)

    def test_staff_cannot_read_cross_user_lists_or_manage_invites(self):
        headers = self.auth(self.staff_token)
        self.assertEqual(self.client.get("/api/schools", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/map-schools", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/all-schools", headers=headers).status_code, 403)
        self.assertEqual(self.client.get("/api/all-emails", headers=headers).status_code, 403)
        self.assertEqual(self.client.get("/api/invitations", headers=headers).status_code, 403)
        self.assertEqual(
            self.client.post("/api/invitations", headers=headers, json={"email": "new@example.com"}).status_code,
            403,
        )
        self.assertEqual(self.client.delete("/api/invitations/1", headers=headers).status_code, 403)
        self.assertEqual(
            self.client.get("/api/all-schools", headers=self.auth(self.admin_token)).status_code,
            200,
        )
        self.assertEqual(
            self.client.get("/api/all-emails", headers=self.auth(self.admin_token)).status_code,
            200,
        )

    def test_registration_requires_exact_unused_invitation(self):
        signup = {"name": "New Staff", "email": "new@example.com", "password": "test-password"}
        self.assertEqual(self.client.post("/api/register", json=signup).status_code, 400)

        created = self.client.post(
            "/api/invitations",
            headers=self.auth(self.admin_token),
            json={"email": "new@example.com"},
        )
        self.assertEqual(created.status_code, 201)
        invite = created.get_json()
        second = self.client.post(
            "/api/invitations",
            headers=self.auth(self.admin_token),
            json={"email": "new@example.com"},
        ).get_json()
        stored = service.db.session.get(service.EmployeeInvitation, invite["id"])
        self.assertNotEqual(stored.token_hash, invite["token"])
        listed = self.client.get("/api/invitations", headers=self.auth(self.admin_token)).get_json()
        self.assertNotIn("token", listed[0])

        wrong_email = {**signup, "email": "wrong@example.com", "invite_token": invite["token"]}
        self.assertEqual(self.client.post("/api/register", json=wrong_email).status_code, 403)
        self.assertEqual(
            self.client.post("/api/register", json={**signup, "invite_token": invite["token"]}).status_code,
            200,
        )
        self.assertEqual(
            self.client.post("/api/register", json={**signup, "invite_token": invite["token"]}).status_code,
            403,
        )
        self.assertIsNotNone(stored.used_at)
        self.assertIsNotNone(service.db.session.get(service.EmployeeInvitation, second["id"]).revoked_at)

    def test_revoked_and_expired_invitations_fail(self):
        headers = self.auth(self.admin_token)
        signup = {"name": "Other", "email": "other@example.com", "password": "test-password"}
        revoked = self.client.post("/api/invitations", headers=headers, json={"email": signup["email"]}).get_json()
        self.assertEqual(self.client.delete(f"/api/invitations/{revoked['id']}", headers=headers).status_code, 200)
        self.assertEqual(
            self.client.post("/api/register", json={**signup, "invite_token": revoked["token"]}).status_code,
            403,
        )

        expired = self.client.post("/api/invitations", headers=headers, json={"email": signup["email"]}).get_json()
        row = service.db.session.get(service.EmployeeInvitation, expired["id"])
        row.expires_at = service.utc_now() - service.timedelta(seconds=1)
        service.db.session.commit()
        self.assertEqual(
            self.client.post("/api/register", json={**signup, "invite_token": expired["token"]}).status_code,
            403,
        )


if __name__ == "__main__":
    unittest.main()
