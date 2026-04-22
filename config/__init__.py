"""
Configuration management for the Mardi Gras API.
"""
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import os

from dotenv import load_dotenv


DEV_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3002",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5555",
    "http://localhost:5556",
]
PROD_ALLOWED_ORIGINS = [
    "https://admin.mardigrasworld.com",
    "https://auth.mardigrasworld.com",
    "https://pixieview-demo.up.railway.app",
]
WEAK_SECRET_VALUES = {
    "",
    "changeme",
    "change-me",
    "your-secret-key",
    "your-super-secret-key-here",
    "dev-secret-key-change-in-production",
}


# Load environment variables
if os.path.exists(".env.local"):
    load_dotenv(".env.local")
elif os.path.exists(".env"):
    load_dotenv(".env")

# For Railway deployment, ensure we can start without .env files
load_dotenv()


def _get_bool_env(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(value):
    return [item.strip() for item in value.split(",") if item.strip()]


def _is_sqlite_url(database_url):
    return database_url.startswith("sqlite:")


def _set_query_parameter(url, key, value):
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[key] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


class Config:
    """Base configuration class."""

    APP_NAME = "mardi-gras-api"
    APP_VERSION = os.environ.get("APP_VERSION", "3.1.0")

    # Basic Flask configuration
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    JSON_SORT_KEYS = False

    # OAuth2 configuration
    AUTH_SERVICE_URL = os.environ.get(
        "AUTH_SERVICE_URL", "https://auth.mardigrasworld.com"
    ).rstrip("/")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)

    @staticmethod
    def get_database_url():
        """Return a normalized database URL."""
        database_url = os.environ.get("DATABASE_URL", "sqlite:///instance/mardi_gras_dev.db")

        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)

        database_ssl_mode = os.environ.get("DATABASE_SSL_MODE")
        if (
            database_ssl_mode
            and database_url.startswith("postgresql://")
            and "sslmode=" not in database_url
        ):
            database_url = _set_query_parameter(database_url, "sslmode", database_ssl_mode)

        return database_url

    SQLALCHEMY_DATABASE_URI = get_database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    if not _is_sqlite_url(SQLALCHEMY_DATABASE_URI):
        SQLALCHEMY_ENGINE_OPTIONS.update(
            {
                "pool_recycle": 300,
                "pool_timeout": 30,
                "max_overflow": 10,
            }
        )

    DEFAULT_ALLOWED_ORIGINS = DEV_ALLOWED_ORIGINS
    ALLOWED_ORIGINS = _split_csv(
        os.environ.get("ALLOWED_ORIGINS", ",".join(DEFAULT_ALLOWED_ORIGINS))
    )

    # Runtime behavior
    TRUST_PROXY_FIX = _get_bool_env("TRUST_PROXY_FIX", False)
    AUTO_INIT_DB = _get_bool_env("AUTO_INIT_DB", True)
    AUTO_SEED_TOUR_EVAL = _get_bool_env("AUTO_SEED_TOUR_EVAL", True)
    CUSTOMER_DATA_AUTH_REQUIRED = _get_bool_env("CUSTOMER_DATA_AUTH_REQUIRED", False)
    TOUR_EVAL_REPORTS_AUTH_REQUIRED = _get_bool_env("TOUR_EVAL_REPORTS_AUTH_REQUIRED", False)
    TOUR_EVAL_ADMIN_AUTH_REQUIRED = _get_bool_env("TOUR_EVAL_ADMIN_AUTH_REQUIRED", False)

    # Mail configuration
    EMAIL_PROVIDER = os.environ.get("EMAIL_PROVIDER")
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = _get_bool_env("MAIL_USE_TLS", True)
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    FROM_EMAIL = os.environ.get("FROM_EMAIL")
    FROM_NAME = os.environ.get("FROM_NAME", "Mardi Gras World")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", FROM_EMAIL or MAIL_USERNAME)
    MGW_COACHING_THRESHOLD = float(os.environ.get("MGW_COACHING_THRESHOLD", "1.3"))
    MGW_REPORT_DEFAULT_EMAILS = os.environ.get("MGW_REPORT_DEFAULT_EMAILS", "")

    # AWS S3 configuration
    S3_BUCKET = os.environ.get("S3_BUCKET_NAME")
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

    # Upload configuration
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024
    MAX_FORM_MEMORY_SIZE = 2 * 1024 * 1024
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")

    # Security headers
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "X-XSS-Protection": "1; mode=block",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }

    @classmethod
    def validate(cls):
        """Validate required configuration for the selected environment."""
        if not cls.AUTH_SERVICE_URL.startswith(("http://", "https://")):
            raise RuntimeError("AUTH_SERVICE_URL must be a valid absolute URL.")

        if not cls.ALLOWED_ORIGINS:
            raise RuntimeError("ALLOWED_ORIGINS must contain at least one origin.")

    @classmethod
    def init_app(cls, app):
        """Finalize configuration after it has been loaded onto the app."""
        cls.validate()


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False
    TESTING = False
    DEFAULT_ALLOWED_ORIGINS = PROD_ALLOWED_ORIGINS
    ALLOWED_ORIGINS = _split_csv(
        os.environ.get("ALLOWED_ORIGINS", ",".join(DEFAULT_ALLOWED_ORIGINS))
    )
    TRUST_PROXY_FIX = _get_bool_env("TRUST_PROXY_FIX", True)
    AUTO_INIT_DB = _get_bool_env("AUTO_INIT_DB", False)
    AUTO_SEED_TOUR_EVAL = _get_bool_env("AUTO_SEED_TOUR_EVAL", False)
    CUSTOMER_DATA_AUTH_REQUIRED = _get_bool_env("CUSTOMER_DATA_AUTH_REQUIRED", True)
    TOUR_EVAL_REPORTS_AUTH_REQUIRED = _get_bool_env("TOUR_EVAL_REPORTS_AUTH_REQUIRED", True)
    TOUR_EVAL_ADMIN_AUTH_REQUIRED = _get_bool_env("TOUR_EVAL_ADMIN_AUTH_REQUIRED", True)

    @classmethod
    def validate(cls):
        super().validate()

        if cls.SECRET_KEY in WEAK_SECRET_VALUES or len(cls.SECRET_KEY) < 32:
            raise RuntimeError(
                "Production SECRET_KEY must be set to a strong, non-default value."
            )

        if cls.JWT_SECRET_KEY in WEAK_SECRET_VALUES or len(cls.JWT_SECRET_KEY) < 32:
            raise RuntimeError(
                "Production JWT_SECRET_KEY must be set to a strong, non-default value."
            )

        if not os.environ.get("DATABASE_URL"):
            raise RuntimeError("Production DATABASE_URL must be configured.")

        if _is_sqlite_url(cls.SQLALCHEMY_DATABASE_URI):
            raise RuntimeError("Production DATABASE_URL must not point to SQLite.")


class TestingConfig(Config):
    """Testing configuration."""

    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    CUSTOMER_DATA_AUTH_REQUIRED = True
    TOUR_EVAL_REPORTS_AUTH_REQUIRED = True
    TOUR_EVAL_ADMIN_AUTH_REQUIRED = True


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}


def get_config(env=None):
    """Return the configuration class for the requested environment."""
    if env is None:
        env = os.environ.get("FLASK_ENV", "development")

    return config_map.get(env, DevelopmentConfig)