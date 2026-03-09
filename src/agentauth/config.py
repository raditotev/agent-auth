"""Application configuration using Pydantic settings."""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "AgentAuth"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = Field(default=False, description="Enable debug mode")

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://agentauth:agentauth_dev_password@localhost:5432/agentauth",
        description="PostgreSQL database URL",
    )

    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis URL for caching and rate limiting",
    )

    # Security
    secret_key: str = Field(
        default="dev-secret-key-change-in-production",
        description="Secret key for signing tokens",
    )
    signing_key_encryption_key: str = Field(
        default="",
        description=(
            "Dedicated AES encryption key for storing private signing keys at rest. "
            "Must be set independently from secret_key in production — if both share "
            "the same value, a single compromise exposes token signing AND key storage. "
            "Falls back to secret_key when empty (development only)."
        ),
    )
    access_token_expire_minutes: int = Field(
        default=15,
        description="Access token expiration time in minutes",
    )
    refresh_token_expire_days: int = Field(
        default=7,
        description="Refresh token expiration time in days",
    )
    issuer_url: str = Field(
        default="https://agentauth.example.com",
        description="Token issuer URL (used in JWT iss claim)",
    )

    # API
    api_v1_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(
        default=["*"],
        description="CORS allowed origins",
    )

    # Rate limiting
    rate_limit_token_requests: int = Field(
        default=30,
        description="Max requests per window for token endpoints (per agent or IP)",
    )
    rate_limit_api_requests: int = Field(
        default=300,
        description="Max requests per window for management API endpoints (per agent or IP)",
    )
    rate_limit_window_seconds: int = Field(
        default=60,
        description="Sliding window duration for rate limiting (seconds)",
    )
    rate_limit_bootstrap_requests: int = Field(
        default=5,
        description=(
            "Max bootstrap/quickstart requests per window per IP. "
            "Stricter than general API limit since these endpoints bypass authentication."
        ),
    )

    # Bootstrap / root-agent self-registration
    bootstrap_token: str | None = Field(
        default=None,
        description=(
            "If set, requests to /agents/bootstrap and /agents/quickstart must supply "
            "this value in the X-Bootstrap-Token header. Strongly recommended in production "
            "to prevent anonymous root-agent creation. Leave unset for open registration "
            "(development only)."
        ),
    )

    # Policy cache
    policy_cache_ttl_seconds: int = Field(
        default=60,
        description="TTL for cached authorization decisions in Redis (seconds)",
    )

    # Webhook delivery
    webhook_max_delivery_attempts: int = Field(
        default=5,
        description="Maximum webhook delivery attempts before giving up",
    )

    # Admin (platform operators only — not agent auth)
    admin_api_key: str | None = Field(
        default=None,
        description="API key for platform admin endpoints (stats, audit). "
        "Set via ADMIN_API_KEY. Required for GET /api/v1/stats and GET /api/v1/audit/events.",
    )

    def validate_production_settings(self) -> list[str]:
        """Check for insecure defaults that must be changed in production.

        Returns a list of warning messages. Raises ValueError in production
        if critical defaults are still in place.
        """
        warnings: list[str] = []
        if self.secret_key == "dev-secret-key-change-in-production":
            warnings.append(
                "SECRET_KEY is using the default dev value. "
                "Set a strong, unique SECRET_KEY environment variable."
            )
        if not self.signing_key_encryption_key:
            warnings.append(
                "SIGNING_KEY_ENCRYPTION_KEY is not set — private signing keys are "
                "encrypted with SECRET_KEY. Set a separate SIGNING_KEY_ENCRYPTION_KEY "
                "so that compromising the token-signing secret does not also expose "
                "the key-at-rest encryption."
            )
        elif self.signing_key_encryption_key == self.secret_key:
            warnings.append(
                "SIGNING_KEY_ENCRYPTION_KEY is identical to SECRET_KEY. "
                "Use a distinct value so the two secrets provide independent protection."
            )
        if self.environment in ("production", "staging") and warnings:
            raise ValueError(
                f"Refusing to start in {self.environment} with insecure defaults: "
                + "; ".join(warnings)
            )
        return warnings

    @property
    def effective_signing_key_encryption_key(self) -> str:
        """Return the key used to encrypt private signing keys at rest.

        Falls back to secret_key in development when
        signing_key_encryption_key is not configured.
        """
        return self.signing_key_encryption_key or self.secret_key


# Global settings instance
settings = Settings()
