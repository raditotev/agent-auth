"""Structlog configuration and stdlib logging integration."""

import logging
import socket
from collections.abc import MutableMapping
from typing import Any

import structlog

get_logger = structlog.get_logger


def _add_logger_name(
    logger: Any,  # noqa: ANN401
    method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Add logger name; tolerates loggers without a .name attribute (e.g. PrintLogger)."""
    record = event_dict.get("_record")
    if record is not None:
        event_dict["logger"] = record.name
    elif hasattr(logger, "name"):
        event_dict["logger"] = logger.name
    return event_dict


def _inject_context_fields(
    logger: Any,  # noqa: ANN401
    method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Inject service-level context fields into every log entry."""
    from agentauth.config import settings

    event_dict.setdefault("service_name", "agentauth")
    event_dict.setdefault("environment", settings.environment)
    event_dict.setdefault("hostname", socket.gethostname())
    return event_dict


def setup_logging() -> None:
    """Configure structlog with a full processor pipeline and wire stdlib logging."""
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        _add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _inject_context_fields,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
        context_class=dict,
        # PrintLoggerFactory writes directly to stdout, bypassing stdlib handlers
        # so structlog records are never double-processed by ProcessorFormatter.
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logging (uvicorn, SQLAlchemy, etc.) through structlog.
    # foreign_pre_chain runs on non-structlog records; _record is available there
    # so _add_logger_name can extract the stdlib logger name correctly.
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

    # Quieten noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
