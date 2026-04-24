from src.models import RiskClass
from src.risk_classifier import RiskClassifier


def test_rbac_is_high():
    m = [{"kind": "ClusterRole", "metadata": {"name": "x"}}]
    assert RiskClassifier().classify(m) == RiskClass.HIGH


def test_waf_configmap_is_low():
    m = [{"kind": "ConfigMap", "metadata": {"name": "modsecurity-rules"}}]
    assert RiskClassifier().classify(m) == RiskClass.LOW


def test_networkpolicy_is_low():
    m = [{"kind": "NetworkPolicy", "metadata": {"name": "allow-redis"}}]
    assert RiskClassifier().classify(m) == RiskClass.LOW


def test_deployment_image_change_is_high():
    m = [{
        "kind": "Deployment",
        "metadata": {
            "name": "target-app",
            "annotations": {"elden-ring/change-kind": "image"},
        },
    }]
    assert RiskClassifier().classify(m) == RiskClass.HIGH


def test_deployment_config_only_is_medium():
    m = [{
        "kind": "Deployment",
        "metadata": {
            "name": "target-app",
            "annotations": {"elden-ring/change-kind": "config-only"},
        },
    }]
    assert RiskClassifier().classify(m) == RiskClass.MEDIUM


def test_mixed_batch_picks_highest():
    m = [
        {"kind": "NetworkPolicy", "metadata": {"name": "np"}},
        {"kind": "ClusterRole",   "metadata": {"name": "cr"}},
    ]
    assert RiskClassifier().classify(m) == RiskClass.HIGH


def test_unknown_is_fail_closed_high():
    m = [{"kind": "CustomResource", "metadata": {"name": "x"}}]
    assert RiskClassifier().classify(m) == RiskClass.HIGH
