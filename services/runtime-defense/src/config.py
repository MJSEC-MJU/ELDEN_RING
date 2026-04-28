"""Environment-based configuration for runtime-defense-controller."""

import os


class Settings:
    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PORT", "8080"))

    REDIS_HOST: str = os.environ.get("REDIS_HOST", "redis-master.elden-monitoring")
    REDIS_PORT: int = int(os.environ.get("REDIS_PORT", "6379"))

    ROUTE_MAP_PATH: str = os.environ.get("ROUTE_MAP_PATH", "/config/routes.json")

    K8S_NAMESPACE: str = os.environ.get("K8S_NAMESPACE", "elden-production")

    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")

    # Webhook auth (Bearer token). Empty value disables enforcement (dev-only).
    WEBHOOK_AUTH_TOKEN: str = os.environ.get("WEBHOOK_AUTH_TOKEN", "")

    # Defense thresholds
    IP_BLOCK_THRESHOLD: int = int(os.environ.get("IP_BLOCK_THRESHOLD", "3"))
    ENDPOINT_DISABLE_THRESHOLD: int = int(os.environ.get("ENDPOINT_DISABLE_THRESHOLD", "5"))
    RATE_LIMIT_RPM: int = int(os.environ.get("RATE_LIMIT_RPM", "10"))


settings = Settings()
