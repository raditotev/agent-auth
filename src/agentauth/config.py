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
        if self.environment == "production" and warnings:
            raise ValueError(
                "Refusing to start in production with insecure defaults: "
                + "; ".join(warnings)
            )
        return warnings


# Global settings instance
settings = Settings()
