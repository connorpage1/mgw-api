"""
Customer data models for Roller sync endpoints.
"""
from datetime import date, datetime

from sqlalchemy import func

from . import db


class Customer(db.Model):
    __tablename__ = "customers"

    id = db.Column(db.Integer, primary_key=True)
    roller_customer_id = db.Column(db.String(255), unique=True, nullable=False)
    postcode = db.Column(db.String(32))
    country = db.Column(db.String(64))
    marketing_acceptance = db.Column(db.Boolean)
    last_sync_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    @classmethod
    def get_by_roller_id(cls, roller_customer_id):
        return cls.query.filter_by(roller_customer_id=roller_customer_id).first()

    @classmethod
    def get_stats(cls, country=None):
        query = cls.query
        if country:
            query = query.filter(cls.country == country)

        total_customers = query.count()
        customers_with_postcode = query.filter(cls.postcode.isnot(None), cls.postcode != "").count()
        customers_without_postcode = total_customers - customers_with_postcode

        return {
            "total_customers": total_customers,
            "customers_with_postcode": customers_with_postcode,
            "customers_without_postcode": customers_without_postcode,
        }

    @classmethod
    def get_zipcode_distribution(cls, country=None, limit=1000):
        query = db.session.query(cls.postcode, func.count(cls.id))
        query = query.filter(cls.postcode.isnot(None), cls.postcode != "")
        if country:
            query = query.filter(cls.country == country)

        return (
            query.group_by(cls.postcode)
            .order_by(func.count(cls.id).desc(), cls.postcode.asc())
            .limit(limit)
            .all()
        )


class RollerDataSync(db.Model):
    __tablename__ = "roller_data_sync"

    id = db.Column(db.Integer, primary_key=True)
    sync_date = db.Column(db.Date, default=date.today, nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    end_time = db.Column(db.DateTime)
    status = db.Column(db.String(32), nullable=False, default="running")
    api_start_date = db.Column(db.Date)
    api_end_date = db.Column(db.Date)
    customers_fetched = db.Column(db.Integer, default=0, nullable=False)
    customers_with_zipcode = db.Column(db.Integer, default=0, nullable=False)
    customers_without_zipcode = db.Column(db.Integer, default=0, nullable=False)
    unique_zipcodes = db.Column(db.Integer, default=0, nullable=False)
    error_message = db.Column(db.Text)

    @classmethod
    def get_latest_successful_sync(cls):
        return (
            cls.query.filter(cls.status == "completed")
            .order_by(cls.end_time.desc().nullslast(), cls.id.desc())
            .first()
        )

    @classmethod
    def get_recent_syncs(cls, limit=5):
        return cls.query.order_by(cls.start_time.desc(), cls.id.desc()).limit(limit).all()

    def to_dict(self):
        return {
            "id": self.id,
            "sync_date": self.sync_date.isoformat() if self.sync_date else None,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status,
            "customers_fetched": self.customers_fetched,
            "customers_with_zipcode": self.customers_with_zipcode,
            "customers_without_zipcode": self.customers_without_zipcode,
            "unique_zipcodes": self.unique_zipcodes,
            "error_message": self.error_message,
            "api_start_date": self.api_start_date.isoformat() if self.api_start_date else None,
            "api_end_date": self.api_end_date.isoformat() if self.api_end_date else None,
        }
