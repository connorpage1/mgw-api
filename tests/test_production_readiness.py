import os
import unittest
from unittest import mock


os.environ.setdefault("FLASK_ENV", "testing")
os.environ.setdefault("SECRET_KEY", "x" * 32)
os.environ.setdefault("JWT_SECRET_KEY", "y" * 32)

from app import create_app
from config import ProductionConfig


class ProductionReadinessTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app.config.update(
            TESTING=True,
            CUSTOMER_DATA_AUTH_REQUIRED=True,
            TOUR_EVAL_REPORTS_AUTH_REQUIRED=True,
            TOUR_EVAL_ADMIN_AUTH_REQUIRED=True,
        )
        self.client = self.app.test_client()

    def test_health_endpoint_reports_database_ready(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["checks"]["database"]["status"], "ok")

    def test_customer_routes_require_auth_when_enabled(self):
        response = self.client.get("/api/customers/stats")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.get_json()["error"], "Missing or invalid authorization header"
        )

    def test_tour_eval_dashboard_routes_require_auth_when_enabled(self):
        response = self.client.get("/api/dashboard/summary")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.get_json()["error"], "Missing or invalid authorization header"
        )

    def test_auth_service_outage_returns_503(self):
        with mock.patch.object(
            self.app.oauth2_service,
            "validate_token",
            return_value={"valid": False, "error": "Auth service unavailable"},
        ):
            response = self.client.get(
                "/api/customers/stats",
                headers={"Authorization": "Bearer demo-token"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error"], "Auth service unavailable")

    def test_public_tour_eval_catalog_remains_accessible(self):
        response = self.client.get("/api/talking-points")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("sections", payload)
        self.assertIn("criteria", payload)

    def test_production_config_rejects_weak_secrets(self):
        class WeakProductionConfig(ProductionConfig):
            SECRET_KEY = "too-short"
            JWT_SECRET_KEY = "also-too-short"
            SQLALCHEMY_DATABASE_URI = "postgresql://db.example.com/mardi_gras"
            ALLOWED_ORIGINS = ["https://admin.mardigrasworld.com"]
            AUTH_SERVICE_URL = "https://auth.mardigrasworld.com"

        with mock.patch.dict(os.environ, {"DATABASE_URL": "postgresql://db.example.com/mardi_gras"}):
            with self.assertRaises(RuntimeError):
                WeakProductionConfig.validate()


if __name__ == "__main__":
    unittest.main()
