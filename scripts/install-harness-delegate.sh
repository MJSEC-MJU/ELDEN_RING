#!/bin/bash
# ============================================================
# ELDEN RING - Harness Delegate 단독 설치 스크립트
# Harness 계정 정보를 입력받아 Delegate를 배포
# ============================================================
# Usage: ./install-harness-delegate.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DELEGATE_YAML="$ROOT_DIR/.harness/delegates/harness-delegate.yaml"

echo "============================================="
echo "  ELDEN RING - Harness Delegate Installer"
echo "============================================="
echo ""

# Harness 계정 정보 입력
read -rp "Harness Account ID: " ACCOUNT_ID
read -rp "Harness Delegate Token: " DELEGATE_TOKEN
read -rp "Harness Manager URL [https://app.harness.io]: " MANAGER_URL
MANAGER_URL="${MANAGER_URL:-https://app.harness.io}"

if [ -z "$ACCOUNT_ID" ] || [ -z "$DELEGATE_TOKEN" ]; then
    echo "ERROR: Account ID and Delegate Token are required."
    exit 1
fi

# Base64 인코딩
TOKEN_B64=$(echo -n "$DELEGATE_TOKEN" | base64 -w0 2>/dev/null || echo -n "$DELEGATE_TOKEN" | base64)

# Namespace 확인/생성
kubectl get namespace elden-harness &>/dev/null || \
    kubectl create namespace elden-harness --dry-run=client -o yaml | kubectl apply -f -

# YAML에 값 주입하여 임시 파일 생성
TEMP_YAML=$(mktemp)
sed \
    -e "s|REPLACE_WITH_BASE64_ENCODED_TOKEN|$TOKEN_B64|g" \
    -e "s|REPLACE_WITH_HARNESS_ACCOUNT_ID|$ACCOUNT_ID|g" \
    -e "s|https://app.harness.io|$MANAGER_URL|g" \
    "$DELEGATE_YAML" > "$TEMP_YAML"

echo ""
echo "Deploying Harness Delegate..."
kubectl apply -f "$TEMP_YAML"
rm -f "$TEMP_YAML"

echo "Waiting for Delegate to be ready..."
kubectl rollout status deployment/harness-delegate -n elden-harness --timeout=300s

echo ""
echo "============================================="
echo "  Harness Delegate deployed successfully!"
echo "  Namespace: elden-harness"
echo "  Delegate Name: elden-ring-delegate"
echo "  Tags: elden-ring, k8s, production"
echo "============================================="
echo ""
echo "Verify in Harness UI: $MANAGER_URL/ng/#/account/$ACCOUNT_ID/delegates"
