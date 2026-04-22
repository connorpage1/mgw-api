"""
Minimal Roller service adapter.
"""
from datetime import datetime, timedelta
import os


class RollerService:
    """Small placeholder adapter that keeps route imports functional."""

    def __init__(self):
        self.token_expires_at = None

    def _get_access_token(self):
        token = os.environ.get("ROLLER_ACCESS_TOKEN")
        if not token:
            raise RuntimeError(
                "Roller API access is not configured. Set ROLLER_ACCESS_TOKEN to enable sync routes."
            )
        self.token_expires_at = datetime.utcnow() + timedelta(minutes=30)
        return token

    def fetch_customers(self, start_date=None, end_date=None):
        self._get_access_token()
        return []

    def fetch_customers_date_range(self, start_date, end_date):
        return self.fetch_customers(start_date=start_date, end_date=end_date)

    def extract_customer_data(self, roller_customer):
        if not isinstance(roller_customer, dict):
            return None

        return {
            "roller_customer_id": roller_customer.get("roller_customer_id") or roller_customer.get("id"),
            "postcode": roller_customer.get("postcode"),
            "country": roller_customer.get("country"),
            "marketing_acceptance": roller_customer.get("marketing_acceptance"),
        }


def create_roller_service():
    return RollerService()
