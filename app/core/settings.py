"""Application settings and configuration."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env.example",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = Field(default="fink-backend", description="Application name")
    app_version: str = Field(default="0.1.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")
    environment: str = Field(default="production", description="Environment")
    crypto_lab_enabled: bool = Field(default=False, description="Enable local-only AES laboratory")
    crypto_lab_event_store_enabled: bool = Field(default=False, description="Enable laboratory event persistence")
    crypto_lab_experimental_enabled: bool = Field(default=False, description="Enable insecure teaching cipher")
    crypto_lab_attacks_enabled: bool = Field(default=False, description="Enable local controlled experiments")
    crypto_lab_attacks_timeout_seconds: float = Field(default=120, gt=0, le=120)
    crypto_lab_anomaly_enabled: bool = Field(default=False, description="Enable synthetic anomaly laboratory")
    crypto_lab_anomaly_timeout_seconds: float = Field(default=120, gt=0, le=120)
    crypto_lab_workers: int = Field(default=1, description="Declared number of lab workers")
    crypto_lab_instances: int = Field(default=1, description="Declared number of lab instances")

    # Database (keep as plain str to satisfy mypy)
    database_url: str = Field(
        default="postgresql+asyncpg://fink:fink@localhost:5432/fink",
        description="Async database URL",
    )
    database_url_sync: str = Field(
        default="postgresql://fink:fink@localhost:5432/fink",
        description="Sync database URL for migrations",
    )

    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )

    # Security
    secret_key: str = Field(
        default="your-secret-key-here-change-in-production",
        description="Secret key for JWT tokens",
    )
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=30,
        description="Access token expiration time in minutes",
    )

    # CORS
    allowed_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080", "http://localhost:5173", "http://172.17.96.1:3000"],
        description="Allowed CORS origins",
    )

    # Pluggy
    pluggy_enabled: bool = Field(default=False, description="Enable the external Pluggy integration")
    pluggy_base_url: str = Field(default="https://api.pluggy.ai", description="Pluggy API base URL")
    pluggy_client_id: str = Field(default="", description="Pluggy client id")
    pluggy_client_secret: str = Field(default="", description="Pluggy client secret")


    # Logging
    log_level: str = Field(default="INFO", description="Logging level")


settings = Settings()
