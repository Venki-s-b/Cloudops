"""
Core configuration — all secrets from environment variables only.
Never hardcode credentials. Use a .env file locally, AWS Secrets Manager in prod.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # pydantic-settings reads these directly from env / .env file
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # JWT
    secret_key: str = ""
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480

    # Database — swap to postgresql://user:pass@host/db in production
    database_url: str = "sqlite:///./cloudops.db"

    # CORS — comma-separated list of allowed origins
    allowed_origins: str = "http://localhost:8001,http://127.0.0.1:8001,http://localhost:3000"

    # Cache TTL (seconds)
    cache_ttl: int = 90

    # Default user credentials (override via env — never hardcode)
    admin_email: str = "admin@company.com"
    admin_password: str = "ChangeMe123!"
    viewer_email: str = "viewer@company.com"
    viewer_password: str = "ChangeMe123!"

    @property
    def origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    def validate_secret_key(self) -> None:
        bad_values = {"", "CHANGE_ME_IN_PRODUCTION_use_secrets_manager", "your-secret-key-here-generate-with-python"}
        if not self.secret_key or self.secret_key in bad_values:
            raise RuntimeError(
                "SECRET_KEY environment variable is not set or is still the placeholder value.\n"
                "Generate a secure key with:\n"
                "  python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if len(self.secret_key) < 32:
            raise RuntimeError(
                "SECRET_KEY must be at least 32 characters long for security."
            )


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.validate_secret_key()
    return s
