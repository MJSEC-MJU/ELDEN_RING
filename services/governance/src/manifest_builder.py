from __future__ import annotations

from typing import Any

from .models import Phase3Result


CANARY_NAMESPACE = "elden-canary"
DEFAULT_DEPLOYMENT_NAME = "target-app"


def build_image_patch_manifests(result: Phase3Result) -> list[dict[str, Any]]:
    annotations = {
        "elden-ring/change-kind": "image",
        "elden-ring/incident": result.incident_id,
    }
    if result.patch_id:
        annotations["elden-ring/patch-id"] = result.patch_id
    if result.cwe_id:
        annotations["elden-ring/cwe"] = result.cwe_id
    if result.target_file:
        annotations["elden-ring/target-file"] = result.target_file

    rollout = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Rollout",
        "metadata": {
            "name": DEFAULT_DEPLOYMENT_NAME,
            "namespace": CANARY_NAMESPACE,
            "annotations": annotations,
        },
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "target-app", "image": result.candidate_image},
                    ],
                },
            },
        },
    }
    return [rollout]
