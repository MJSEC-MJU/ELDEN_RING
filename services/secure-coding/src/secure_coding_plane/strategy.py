from __future__ import annotations

from typing import Any

from .schemas import PatchStrategy, StrategyResponse
from .storage import PlaneStore
from .utils import dump_model, generate_id, write_json


class SecureCodingStrategyEngine:
    def __init__(self, store: PlaneStore, artifact_root) -> None:
        self.store = store
        self.artifact_root = artifact_root

    def run_strategy(self, job_id: str, context: dict[str, Any]) -> StrategyResponse:
        self.store.update_secure_job(job_id, status="STRATEGY_GENERATING", current_step="strategy", progress=40)
        strategy = self.make_strategy(context["attack_info"]["cwe_id"], context["target"]["source_mapping"]["function"])
        payload = StrategyResponse(job_id=job_id, status="success", strategy=strategy)
        write_json(self.artifact_root / "strategy" / f"{job_id}.json", dump_model(payload))
        self.store.save_secure_strategy(job_id, dump_model(strategy))
        return payload

    def make_strategy(self, cwe_id: str, function_name: str) -> PatchStrategy:
        if cwe_id == "CWE-89":
            return PatchStrategy(
                strategy_id=generate_id("strategy"),
                root_cause="사용자 입력이 문자열 포매팅을 통해 SQL 쿼리에 직접 삽입되고 있음",
                fix_goal=f"{function_name} 함수의 SQL Injection 취약점을 제거하면서 기존 API 동작을 유지한다",
                fix_actions=["문자열 기반 SQL 조합 제거", "파라미터 바인딩 방식으로 변경", "오류 세부정보 직접 노출 금지"],
                constraints=self.default_constraints(),
            )
        if cwe_id == "CWE-79":
            return PatchStrategy(
                strategy_id=generate_id("strategy"),
                root_cause="사용자 입력이 출력 직전에 escape 없이 HTML sink로 전달되고 있음",
                fix_goal=f"{function_name} 함수의 XSS 취약점을 제거하면서 기존 응답 구조를 유지한다",
                fix_actions=["출력 직전 HTML escape 적용", "위험 sink 직결 제거", "정상 응답 구조 유지"],
                constraints=self.default_constraints(),
            )
        return PatchStrategy(
            strategy_id=generate_id("strategy"),
            root_cause="사용자 입력이 경로 검증 없이 파일 시스템 접근에 사용되고 있음",
            fix_goal=f"{function_name} 함수의 Path Traversal 취약점을 제거하면서 기존 파일 접근 기능을 유지한다",
            fix_actions=["base directory 고정", "resolve 기반 canonical path 검증", "허용 경로 이탈 시 차단"],
            constraints=self.default_constraints(),
        )

    def default_constraints(self) -> dict[str, Any]:
        return {
            "preserve_function_signature": True,
            "preserve_response_schema": True,
            "minimal_change_only": True,
            "allow_new_dependency": False,
            "do_not_modify_unrelated_logic": True,
        }
