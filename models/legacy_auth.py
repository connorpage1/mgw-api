"""
Legacy auth models kept for schema compatibility.
"""
from datetime import datetime

from . import db


roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer, db.ForeignKey("users.id"), primary_key=True),
    db.Column("role_id", db.Integer, db.ForeignKey("roles.id"), primary_key=True),
)


class User(db.Model):
    """Minimal local user model retained for legacy foreign keys."""

    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    roles = db.relationship(
        "Role",
        secondary=roles_users,
        lazy="selectin",
        backref=db.backref("users", lazy="dynamic"),
    )

    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)


class Role(db.Model):
    """Minimal role model retained for legacy compatibility."""

    __tablename__ = "roles"
    __table_args__ = {"extend_existing": True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))

