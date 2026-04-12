from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GOV_", extra="ignore")

    redis_url: str = "redis://redis-master.elden-monitoring:6379/0"
    redis_promote_channel: str = "elden:phase4:promote"
    redis_retry_channel: str = "elden:phase2:retry"

    staging_namespace: str = "elden-staging"
    canary_namespace: str = "elden-canary"
    prod_namespace: str = "elden-production"
    governance_namespace: str = "elden-governance"

    ra_exploit_cm: str = "ra-exploit-results"
    ra_regression_cm: str = "ra-regression-results"
    ra_slo_cm: str = "ra-slo-results"

    promotion_policy_cm: str = "promotion-policy"

    prometheus_url: str = "http://prometheus-kube-prometheus-prometheus.elden-monitoring:9090"

    github_repo: str = "MJSEC-MJU/ELDEN_RING"
    github_token: str = ""
    defense_branch_prefix: str = "defense/inc-"
    base_branch: str = "dev"

    argocd_server: str = "http://argocd-server.argocd.svc.cluster.local"
    argocd_token: str = ""

    shadow_app: str = "elden-shadow"
    prod_app: str = "elden-prod"

    canary_error_rate_threshold: float = 0.05
    canary_latency_p99_ms_threshold: float = 1000.0

    log_level: str = "INFO"


settings = Settings()
