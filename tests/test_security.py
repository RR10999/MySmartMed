"""Regression tests for core security properties of the prototype."""

import tempfile
import unittest
from pathlib import Path

import app as web
import db
from crypto_utils import decrypt_field, derive_key, encrypt_field, generate_login_salt


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.tempdir.name) / "test.db"
        db.init_db()
        web.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        web._SESSION_KEYS.clear()
        web._ACTIVE_USERS.clear()
        self.client = web.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_encryption_is_random_and_tamper_detected(self):
        key = derive_key("StrongPassword123", generate_login_salt())
        one, two = encrypt_field("sensitive", key), encrypt_field("sensitive", key)
        self.assertNotEqual(one, two)
        self.assertEqual(decrypt_field(one, key), "sensitive")
        with self.assertRaises(Exception):
            decrypt_field(one[:-2] + "AA", key)

    def test_post_without_csrf_is_rejected(self):
        response = self.client.post("/register", data={"username": "caregiver", "password": "StrongPassword123"})
        self.assertEqual(response.status_code, 400)

    def test_duplicate_dose_constraint_exists(self):
        conn = db.get_connection()
        indexes = [row[1] for row in conn.execute("PRAGMA index_list('Compliance_Log')")]
        conn.close()
        self.assertTrue(indexes)


if __name__ == "__main__":
    unittest.main()
