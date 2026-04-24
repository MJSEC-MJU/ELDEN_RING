"""Lv.1 Defense: Rate Limit via Istio EnvoyFilter."""

import logging

logger = logging.getLogger(__name__)


async def apply_rate_limit(source_ip: str, requests_per_minute: int = 10):
    """
    Create an Istio EnvoyFilter to rate-limit a specific IP.
    In non-K8s environments, this logs the action without applying.
    """
    envoy_filter = {
        "apiVersion": "networking.istio.io/v1alpha3",
        "kind": "EnvoyFilter",
        "metadata": {
            "name": f"ratelimit-{source_ip.replace('.', '-')}",
            "namespace": "elden-production",
        },
        "spec": {
            "workloadSelector": {"labels": {"app": "target-app"}},
            "configPatches": [
                {
                    "applyTo": "HTTP_FILTER",
                    "match": {
                        "context": "SIDECAR_INBOUND",
                        "listener": {
                            "filterChain": {
                                "filter": {
                                    "name": "envoy.filters.network.http_connection_manager"
                                }
                            }
                        },
                    },
                    "patch": {
                        "operation": "INSERT_BEFORE",
                        "value": {
                            "name": "envoy.filters.http.local_ratelimit",
                            "typed_config": {
                                "@type": "type.googleapis.com/udpa.type.v1.TypedStruct",
                                "type_url": "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
                                "value": {
                                    "stat_prefix": f"rate_limit_{source_ip.replace('.', '_')}",
                                    "token_bucket": {
                                        "max_tokens": requests_per_minute,
                                        "tokens_per_fill": requests_per_minute,
                                        "fill_interval": "60s",
                                    },
                                    "filter_enabled": {
                                        "runtime_key": "local_rate_limit_enabled",
                                        "default_value": {
                                            "numerator": 100,
                                            "denominator": "HUNDRED",
                                        },
                                    },
                                    "filter_enforced": {
                                        "runtime_key": "local_rate_limit_enforced",
                                        "default_value": {
                                            "numerator": 100,
                                            "denominator": "HUNDRED",
                                        },
                                    },
                                },
                            },
                        },
                    },
                }
            ],
        },
    }

    try:
        from kubernetes import client

        api = client.CustomObjectsApi()
        api.create_namespaced_custom_object(
            group="networking.istio.io",
            version="v1alpha3",
            namespace="elden-production",
            plural="envoyfilters",
            body=envoy_filter,
        )
        logger.info(f"Lv.1 Rate limit applied for IP {source_ip} ({requests_per_minute} rpm)")
    except Exception as e:
        logger.warning(f"Lv.1 Rate limit for {source_ip} (K8s unavailable: {e})")
