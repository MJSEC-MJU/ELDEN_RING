import asyncio
import json
import logging

import redis.asyncio as redis

from .config import settings
from .git_writer import GitWriter
from .k8s_client import K8sClient
from .models import (
    Phase3Result,
    PromotionRequest,
    PromotionStage,
    RiskClass,
    ValidationStatus,
)
from .policy_gate import PolicyGate
from .promotion_gate import PromotionGate
from .risk_classifier import RiskClassifier

logger = logging.getLogger(__name__)


class Orchestrator:
    """Top-level state machine: Phase 3 PASSED → A gate → B git PR → C rollout.

    Subscribes to `elden:phase4:promote` and drives each incident through
    the three governance layers. Failures are NOT auto-retried here —
    they are published to `elden:phase2:retry` for the secure-coding plane.
    """

    def __init__(self, k8s: K8sClient):
        self.k8s = k8s
        self.classifier = self._load_classifier()
        self.policy_gate = PolicyGate(k8s, settings.canary_namespace)
        self.promotion_gate = PromotionGate(k8s)
        self.git: GitWriter | None = None
        if settings.github_token:
            self.git = GitWriter(
                settings.github_repo,
                settings.github_token,
                settings.base_branch,
                settings.defense_branch_prefix,
            )
        else:
            logger.warning("GOV_GITHUB_TOKEN unset — git_writer disabled (dry-run mode)")
        self._state: dict[str, PromotionRequest] = {}

    def _load_classifier(self) -> RiskClassifier:
        data = self.k8s.read_configmap(
            settings.governance_namespace, settings.promotion_policy_cm,
        )
        return RiskClassifier(data.get("policy.yaml"))

    async def run(self) -> None:
        client = redis.from_url(settings.redis_url, decode_responses=True)
        pubsub = client.pubsub()
        await pubsub.subscribe(settings.redis_promote_channel)
        logger.info("orchestrator subscribed to %s", settings.redis_promote_channel)
        async for msg in pubsub.listen():
            if msg.get("type") != "message":
                continue
            try:
                payload = json.loads(msg["data"])
                await self._handle(Phase3Result(**payload), client)
            except Exception as e:
                logger.exception("promote handler failed: %s", e)

    async def _handle(self, result: Phase3Result, client: redis.Redis) -> None:
        incident = result.incident_id
        logger.info("handling incident=%s image=%s", incident, result.candidate_image)
        if not result.all_passed:
            await self._reject_to_retry(result, client)
            return

        risk = self.classifier.classify(result.manifests)
        req = PromotionRequest(
            incident_id=incident,
            risk=risk,
            stage=PromotionStage.POLICY_CHECK,
            branch="",
            reason=f"risk={risk.value}",
        )
        self._state[incident] = req

        # B layer — open defense-candidate PR
        if self.git:
            branch, pr = self.git.create_defense_pr(
                incident,
                result.manifests,
                risk.value,
                self._summarize(result),
            )
            req.branch, req.pr_number = branch, pr
        else:
            req.branch = f"{settings.defense_branch_prefix}{incident}"
        req.stage = PromotionStage.GIT_PR

        # A layer — wait for Kyverno reports after ArgoCD sync
        await asyncio.sleep(30)  # allow applicationset + kyverno to process
        gate = self.policy_gate.evaluate(incident)
        if not gate.passed:
            logger.warning("policy gate FAILED incident=%s violations=%s",
                           incident, gate.violations)
            await self._reject_to_retry(result, client)
            return

        # C layer — allow rollout to proceed based on risk
        req.stage = PromotionStage.CANARY_ANALYSIS
        self.promotion_gate.resume_if_allowed(
            req.rollout_namespace, req.rollout_name, req.risk,
        )
        if req.risk == RiskClass.HIGH:
            req.stage = PromotionStage.MANUAL_APPROVAL
            logger.info("incident=%s awaiting manual approval (high risk)", incident)
        else:
            req.stage = PromotionStage.COMPLETED

    async def _reject_to_retry(self, result: Phase3Result, client: redis.Redis) -> None:
        payload = {
            "incident_id": result.incident_id,
            "reason": "governance_rejected",
            "exploit": result.exploit,
            "regression": result.regression,
            "slo": result.slo,
        }
        await client.publish(settings.redis_retry_channel, json.dumps(payload))
        logger.info("rejected incident=%s → %s", result.incident_id, settings.redis_retry_channel)

    @staticmethod
    def _summarize(r: Phase3Result) -> str:
        return (
            f"- exploit replay: **{r.exploit}**\n"
            f"- regression:    **{r.regression}**\n"
            f"- SLO:           **{r.slo}**\n"
            f"- candidate:     `{r.candidate_image}`"
        )

    def snapshot(self) -> list[PromotionRequest]:
        return list(self._state.values())
