"""Centralized Celery application configuration.

Usage — start a worker:
    uv run celery -A agentauth.tasks.celery_app worker --loglevel=info

Usage — start the beat scheduler for periodic tasks:
    uv run celery -A agentauth.tasks.celery_app beat --loglevel=info
"""

from celery import Celery  # type: ignore[import-untyped]
from celery.signals import worker_process_init  # type: ignore[import-untyped]

from agentauth.config import settings


@worker_process_init.connect  # type: ignore[untyped-decorator]
def init_worker_logging(**kwargs: object) -> None:  # noqa: ARG001
    """Set up structlog in each Celery worker process."""
    from agentauth.core.logging import setup_logging

    setup_logging()


celery_app = Celery(
    "agentauth",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "agentauth.tasks.key_rotation",
        "agentauth.tasks.credential_sync",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes hard limit
    task_soft_time_limit=240,  # 4 minutes soft limit
    beat_schedule={
        "rotate-signing-keys-daily": {
            "task": "agentauth.rotate_signing_keys",
            "schedule": 86400.0,  # Every 24 hours
            "options": {"expires": 3600},
        },
        "flush-credential-last-used": {
            "task": "agentauth.flush_credential_last_used",
            "schedule": 60.0,  # Every 60 seconds
            "options": {"expires": 55},
        },
    },
)
