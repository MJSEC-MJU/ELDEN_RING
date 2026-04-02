#!/bin/bash
# ============================================================
# ELDEN RING - Kubernetes Cluster Setup Script
# 전체 인프라를 순서대로 구축하는 원클릭 스크립트
# ============================================================
# Usage: ./setup-cluster.sh [--dev|--prod]
#   --dev  : kind 클러스터로 로컬 개발 환경 구축
#   --prod : 기존 클러스터에 인프라 배포
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
K8S_DIR="$ROOT_DIR/kubernetes"
HARNESS_DIR="$ROOT_DIR/.harness"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

MODE="${1:---dev}"

# ============================================================
# Step 0: Prerequisites check
# ============================================================
check_prerequisites() {
    log_info "Checking prerequisites..."
    local missing=()

    for cmd in kubectl helm; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ "$MODE" = "--dev" ] && ! command -v kind &>/dev/null; then
        missing+=("kind")
    fi

    if ! command -v istioctl &>/dev/null; then
        log_warn "istioctl not found - Istio will be installed via helm fallback"
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        log_error "Install them before proceeding."
        exit 1
    fi

    log_ok "All prerequisites met"
}

# ============================================================
# Step 1: Create Kind cluster (dev mode only)
# ============================================================
create_kind_cluster() {
    if [ "$MODE" != "--dev" ]; then
        log_info "Skipping kind cluster creation (production mode)"
        return
    fi

    log_info "Creating kind cluster: elden-ring..."

    if kind get clusters 2>/dev/null | grep -q "elden-ring"; then
        log_warn "Cluster 'elden-ring' already exists. Skipping creation."
        kind export kubeconfig --name elden-ring
        return
    fi

    cat <<'EOF' | kind create cluster --name elden-ring --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
    extraPortMappings:
      - containerPort: 80
        hostPort: 80
        protocol: TCP
      - containerPort: 443
        hostPort: 443
        protocol: TCP
      - containerPort: 30000
        hostPort: 30000
        protocol: TCP
  - role: worker
    labels:
      elden-ring/role: workload
  - role: worker
    labels:
      elden-ring/role: workload
  - role: worker
    labels:
      elden-ring/role: monitoring
EOF

    log_ok "Kind cluster 'elden-ring' created (1 control-plane + 3 workers)"
}

# ============================================================
# Step 2: Apply base K8s resources
# ============================================================
apply_base_resources() {
    log_info "Applying base Kubernetes resources..."

    log_info "  -> Namespaces"
    kubectl apply -f "$K8S_DIR/base/namespaces.yaml"

    log_info "  -> RBAC"
    kubectl apply -f "$K8S_DIR/base/rbac.yaml"

    log_info "  -> Network Policies"
    kubectl apply -f "$K8S_DIR/base/network-policies.yaml"

    log_info "  -> Resource Quotas"
    kubectl apply -f "$K8S_DIR/base/resource-quotas.yaml"

    log_ok "Base resources applied"
}

# ============================================================
# Step 3: Install Istio service mesh
# ============================================================
install_istio() {
    log_info "Installing Istio service mesh..."

    if command -v istioctl &>/dev/null; then
        istioctl install -f "$K8S_DIR/service-mesh/istio/istio-operator.yaml" -y
    else
        log_info "Using helm to install Istio..."
        helm repo add istio https://istio-release.storage.googleapis.com/charts
        helm repo update

        helm upgrade --install istio-base istio/base \
            --namespace istio-system --create-namespace --wait

        helm upgrade --install istiod istio/istiod \
            --namespace istio-system --wait --timeout 5m

        helm upgrade --install istio-ingress istio/gateway \
            --namespace istio-system --wait
    fi

    # Gateway 및 라우팅 규칙 적용
    kubectl apply -f "$K8S_DIR/service-mesh/istio/gateway.yaml"

    log_ok "Istio installed and configured"
}

# ============================================================
# Step 4: Install monitoring stack
# ============================================================
install_monitoring() {
    log_info "Installing monitoring stack..."

    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add grafana https://grafana.github.io/helm-charts
    helm repo update

    log_info "  -> Prometheus + Grafana"
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
        --namespace elden-monitoring \
        --values "$K8S_DIR/monitoring/prometheus/values.yaml" \
        --wait --timeout 10m

    log_info "  -> Loki (로그 수집)"
    helm upgrade --install loki grafana/loki-stack \
        --namespace elden-monitoring \
        --values "$K8S_DIR/monitoring/loki/values.yaml" \
        --wait --timeout 10m

    log_ok "Monitoring stack installed"
}

# ============================================================
# Step 5: Install Falco security monitoring
# ============================================================
install_falco() {
    log_info "Installing Falco security monitoring..."

    helm repo add falcosecurity https://falcosecurity.github.io/charts
    helm repo update

    helm upgrade --install falco falcosecurity/falco \
        --namespace elden-monitoring \
        --values "$K8S_DIR/security/falco/values.yaml" \
        --wait --timeout 10m

    log_ok "Falco installed"
}

# ============================================================
# Step 6: Deploy Harness Delegate
# ============================================================
deploy_harness_delegate() {
    log_info "Deploying Harness Delegate..."

    if kubectl get deployment harness-delegate -n elden-harness &>/dev/null; then
        log_warn "Harness Delegate already deployed. Skipping."
        return
    fi

    # Token이 설정되었는지 확인
    local delegate_yaml="$HARNESS_DIR/delegates/harness-delegate.yaml"
    if grep -q "REPLACE_WITH" "$delegate_yaml"; then
        log_warn "Harness Delegate YAML contains placeholder values."
        log_warn "Edit $delegate_yaml with your Harness account credentials before deploying."
        log_warn "Skipping Harness Delegate deployment for now."
        return
    fi

    kubectl apply -f "$delegate_yaml"
    kubectl rollout status deployment/harness-delegate -n elden-harness --timeout=300s

    log_ok "Harness Delegate deployed"
}

# ============================================================
# Step 7: Deploy sample target application
# ============================================================
deploy_target_app() {
    log_info "Deploying target application to environments..."

    log_info "  -> Production"
    kubectl apply -f "$K8S_DIR/environments/production/deployment.yaml"

    log_info "  -> Staging"
    kubectl apply -f "$K8S_DIR/environments/staging/deployment.yaml"

    log_ok "Target application deployed"
}

# ============================================================
# Step 8: Verify everything
# ============================================================
verify_installation() {
    log_info "Verifying installation..."
    echo ""
    echo "============================================="
    echo "  ELDEN RING Infrastructure Status"
    echo "============================================="
    echo ""

    echo "--- Namespaces ---"
    kubectl get namespaces -l app.kubernetes.io/part-of=elden-ring \
        -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,PLANE:.metadata.labels.elden-ring/plane

    echo ""
    echo "--- Pods (all ELDEN RING namespaces) ---"
    for ns in elden-production elden-staging elden-canary elden-secure-coding elden-governance elden-monitoring elden-harness; do
        PODS=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | wc -l)
        if [ "$PODS" -gt 0 ]; then
            echo "[$ns]"
            kubectl get pods -n "$ns" --no-headers 2>/dev/null | head -5
            echo ""
        fi
    done

    echo "--- Resource Quotas ---"
    kubectl get resourcequota -A -l app.kubernetes.io/part-of=elden-ring 2>/dev/null || true

    echo ""
    echo "--- Istio Status ---"
    kubectl get pods -n istio-system --no-headers 2>/dev/null | head -5

    echo ""
    echo "============================================="
    echo "  ELDEN RING Infrastructure Ready!"
    echo "============================================="
    echo ""
    echo "  Grafana:  kubectl port-forward svc/prometheus-grafana -n elden-monitoring 3000:80"
    echo "  Prometheus: kubectl port-forward svc/prometheus-kube-prometheus-prometheus -n elden-monitoring 9090:9090"
    echo ""
    echo "  Next steps:"
    echo "  1. Configure Harness Delegate credentials"
    echo "  2. Team members can now deploy their Plane components:"
    echo "     - Runtime Defense Plane  -> elden-production"
    echo "     - Secure Coding Plane    -> elden-secure-coding"
    echo "     - Recovery Assurance     -> elden-staging"
    echo "     - Governance Plane       -> elden-governance"
    echo "============================================="
}

# ============================================================
# Main
# ============================================================
main() {
    echo ""
    echo "============================================="
    echo "  ELDEN RING - Infrastructure Setup"
    echo "  Mode: $MODE"
    echo "============================================="
    echo ""

    check_prerequisites
    create_kind_cluster
    apply_base_resources
    install_istio
    install_monitoring
    install_falco
    deploy_harness_delegate
    deploy_target_app
    verify_installation
}

main
