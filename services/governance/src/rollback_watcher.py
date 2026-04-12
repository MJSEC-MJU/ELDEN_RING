import asyncio
import logging

import httpx

from .k8s_client import K8sClient
from .promotion_gate import PromotionGate

logger = logging.getLogger(__name__)


class RollbackWatcher:
    """Watches canary SLO via Prometheus; if either threshold breached for
    two consecutive polls, triggers Rollout abort (auto-rollback).

    Argo Rollouts AnalysisTemplate already does this for canary steps;
    this watcher is a safety net for *post-promotion* drift on the
    stable side (elden-canary → elden-production).
    """

    def __init__(
        self,
        prom_url: str,
        gate: PromotionGate,
        namespace: str,
        rollout: str,
        err_threshold: float,
        p99_threshold_ms: float,
        poll_interval: float = 30.0,
    ):
        self.prom_url = prom_url
        self.gate = gate
        self.namespace = namespace
        self.rollout = rollout
        self.err_threshold = err_threshold
        self.p99_threshold = p99_threshold_ms
        self.poll_interval = poll_interval
        self._consecutive_breaches = 0

    async def run(self, service: str) -> None:
        async with httpx.AsyncClient(timeout=5.0) as client:
            while True:
                try:
                    err = await self._query_error_rate(client, service)
                    p99 = await self._query_p99(client, service)
                    breach = err > self.err_threshold or p99 > self.p99_threshold
                    if breach:
                        self._consecutive_breaches += 1
                        logger.warning(
                            "SLO breach %d/2 service=%s err=%.4f p99=%.1fms",
                            self._consecutive_breaches, service, err, p99,
                        )
                        if self._consecutive_breaches >= 2:
                            self.gate.abort(
                                self.namespace, self.rollout,
                                f"slo_breach err={err:.3f} p99={p99:.0f}ms",
                            )
                            self._consecutive_breaches = 0
                    else:
                        self._consecutive_breaches = 0
                except Exception as e:
                    logger.error("watcher tick failed: %s", e)
                await asyncio.sleep(self.poll_interval)

    async def _query_error_rate(self, client: httpx.AsyncClient, service: str) -> float:
        q = (
            f'sum(rate(istio_requests_total{{destination_service_name="{service}",'
            f'destination_service_namespace="{self.namespace}",response_code=~"5.."}}[1m]))'
            f' / '
            f'sum(rate(istio_requests_total{{destination_service_name="{service}",'
            f'destination_service_namespace="{self.namespace}"}}[1m]))'
        )
        return await self._prom_scalar(client, q)

    async def _query_p99(self, client: httpx.AsyncClient, service: str) -> float:
        q = (
            f'histogram_quantile(0.99, sum(rate(istio_request_duration_milliseconds_bucket'
            f'{{destination_service_name="{service}",destination_service_namespace="{self.namespace}"}}[1m]))'
            f' by (le))'
        )
        return await self._prom_scalar(client, q)

    async def _prom_scalar(self, client: httpx.AsyncClient, query: str) -> float:
        r = await client.get(f"{self.prom_url}/api/v1/query", params={"query": query})
        r.raise_for_status()
        data = r.json().get("data", {}).get("result", [])
        if not data:
            return 0.0
        return float(data[0]["value"][1])
