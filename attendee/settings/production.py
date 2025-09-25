import os

import dj_database_url

from .base import *

DEBUG = False
ALLOWED_HOSTS = ["*"]

"""Production settings.

Note on database SSL:
Original configuration forced ssl_require=True which breaks when running
inside an internal Docker network against a plain (non-SSL) Postgres
container (common for self-hosted or local deployments). That resulted in
"server does not support SSL, but SSL was required" during migrations.

We now make this configurable via the environment variable DB_SSL_REQUIRE.

Behaviour:
1. If DB_SSL_REQUIRE is explicitly set (true/false, 1/0, yes/no, on/off)
   we respect it.
2. Otherwise we auto-disable SSL if the DATABASE_URL points to an internal
   host name typical for docker (mrmeet-postgres, postgres, localhost, 127.0.0.1).
3. Fallback default is to require SSL (safer for real production).

Set DB_SSL_REQUIRE=false in docker-compose for internal Postgres.
"""


def _bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


_db_url = os.getenv("DATABASE_URL", "")
_internal_hosts = {"mrmeet-postgres", "postgres", "localhost", "127.0.0.1"}
_looks_internal = any(
    f"@{h}:" in _db_url or _db_url.startswith(f"postgres://{h}:")
    for h in _internal_hosts
)

# Default rule: require SSL unless looks internal.
_default_ssl_require = not _looks_internal
_ssl_require = _bool_env("DB_SSL_REQUIRE", _default_ssl_require)

DATABASES = {
    "default": dj_database_url.config(
        env="DATABASE_URL",
        conn_max_age=600,
        conn_health_checks=True,
        ssl_require=_ssl_require,
    ),
}

# PRESERVE CELERY TASKS IF WORKER IS SHUT DOWN
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_REJECT_ON_WORKER_LOST = True

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 60
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

if os.getenv("DISABLE_EMAIL_VERIFICATION", "false").lower() in ("1", "true", "yes"):
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
    EMAIL_HOST = "smtp.mailgun.org"
    EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
    EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
    EMAIL_PORT = 587
    EMAIL_USE_TLS = True
    DEFAULT_FROM_EMAIL = "noreply@mail.attendee.dev"

    ADMINS = []

    if os.getenv("ERROR_REPORTS_RECEIVER_EMAIL_ADDRESS"):
        ADMINS.append(
            (
                "Attendee Error Reports Email Receiver",
                os.getenv("ERROR_REPORTS_RECEIVER_EMAIL_ADDRESS"),
            )
        )

    SERVER_EMAIL = "noreply@mail.attendee.dev"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": os.getenv("ATTENDEE_LOG_LEVEL", "INFO"),
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": os.getenv("ATTENDEE_LOG_LEVEL", "INFO"),
            "propagate": False,
        },
    },
}
