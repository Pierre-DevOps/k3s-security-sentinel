#!/usr/bin/env python3
"""
K3s Security Sentinel — Security Scanner
Collecte les findings de sécurité K8s et expose des métriques Prometheus.
"""

import os
import time
import logging
from prometheus_client import start_http_server, Gauge, Counter
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("security-sentinel")

SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", 300))

_raw_excluded = os.environ.get(
    "EXCLUDED_NAMESPACES",
    "kube-system,kube-public,kube-node-lease"
)
EXCLUDED_NAMESPACES = {ns.strip() for ns in _raw_excluded.split(",") if ns.strip()}

SECRET_KEYWORDS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "auth", "credential", "private_key", "access_key", "db_pass",
    "jwt", "bearer",
}

# ─── Métriques Prometheus ──────────────────────────────────────────────────────
RISK_SCORE       = Gauge("security_risk_score", "Score de risque global 0-100")
ROOT_CONTAINERS  = Gauge("security_root_containers_total", "Containers sans runAsNonRoot")
MISSING_NETPOL   = Gauge("security_missing_networkpolicy_total", "Namespaces sans NetworkPolicy")
EXPOSED_SECRETS  = Gauge("security_exposed_secrets_total", "Secrets en clair dans env vars")
PRIVILEGED_SA    = Gauge("security_privileged_serviceaccounts_total", "ServiceAccounts trop permissifs")
EXPOSED_NODEPORT = Gauge("security_exposed_nodeports_total", "NodePorts hors liste blanche")
SCAN_DURATION    = Gauge("security_scan_duration_seconds", "Durée du dernier scan")
SCAN_ERRORS      = Counter("security_scan_errors_total", "Erreurs de scan", ["check_type"])


def get_allowed_nodeports() -> set:
    """Lit ALLOWED_NODEPORTS depuis l'env à chaque appel — pas au démarrage."""
    raw = os.environ.get("ALLOWED_NODEPORTS", "")
    return {int(p.strip()) for p in raw.split(",") if p.strip().isdigit()}


def get_namespaces(v1: client.CoreV1Api) -> list:
    try:
        return [
            ns.metadata.name
            for ns in v1.list_namespace().items
            if ns.metadata.name not in EXCLUDED_NAMESPACES
        ]
    except ApiException as e:
        log.error(f"[namespaces] {e}")
        SCAN_ERRORS.labels(check_type="list_namespaces").inc()
        return []


def check_root_containers(v1: client.CoreV1Api, namespaces: list) -> dict:
    findings = []
    try:
        for ns in namespaces:
            for pod in v1.list_namespaced_pod(namespace=ns).items:
                pod_sc = pod.spec.security_context or client.V1PodSecurityContext()
                for container in pod.spec.containers + (pod.spec.init_containers or []):
                    c_sc = container.security_context or client.V1SecurityContext()
                    if c_sc.run_as_non_root is False:
                        reason = "runAsNonRoot: false"
                    elif (
                        c_sc.run_as_non_root is None
                        and pod_sc.run_as_non_root is not True
                    ):
                        if c_sc.run_as_user == 0 or pod_sc.run_as_user == 0:
                            reason = "runAsUser: 0"
                        else:
                            reason = "runAsNonRoot absent"
                    else:
                        continue
                    findings.append({
                        "namespace": ns,
                        "pod": pod.metadata.name,
                        "container": container.name,
                        "reason": reason,
                        "severity": "HIGH",
                    })
    except ApiException as e:
        log.error(f"[root_containers] {e}")
        SCAN_ERRORS.labels(check_type="root_containers").inc()
    return {"findings": findings, "count": len(findings)}


def check_network_policies(v1: client.CoreV1Api, networking: client.NetworkingV1Api, namespaces: list) -> dict:
    findings = []
    try:
        for ns in namespaces:
            pods = v1.list_namespaced_pod(namespace=ns).items
            if not pods:
                continue
            netpols = networking.list_namespaced_network_policy(namespace=ns).items
            if not netpols:
                findings.append({
                    "namespace": ns,
                    "pod_count": len(pods),
                    "severity": "CRITICAL",
                    "reason": f"{len(pods)} pods sans NetworkPolicy",
                })
    except ApiException as e:
        log.error(f"[network_policies] {e}")
        SCAN_ERRORS.labels(check_type="network_policies").inc()
    return {"findings": findings, "count": len(findings)}


def check_exposed_secrets(v1: client.CoreV1Api, namespaces: list) -> dict:
    findings = []
    try:
        for ns in namespaces:
            for pod in v1.list_namespaced_pod(namespace=ns).items:
                for container in pod.spec.containers:
                    for env in (container.env or []):
                        if (
                            any(kw in env.name.lower() for kw in SECRET_KEYWORDS)
                            and env.value
                            and not env.value_from
                        ):
                            findings.append({
                                "namespace": ns,
                                "pod": pod.metadata.name,
                                "container": container.name,
                                "env_var": env.name,
                                "severity": "CRITICAL",
                                "reason": "Secret en clair dans env var",
                            })
    except ApiException as e:
        log.error(f"[exposed_secrets] {e}")
        SCAN_ERRORS.labels(check_type="exposed_secrets").inc()
    return {"findings": findings, "count": len(findings)}


def check_exposed_nodeports(v1: client.CoreV1Api, namespaces: list) -> dict:
    allowed = get_allowed_nodeports()
    log.info(f"   Liste blanche NodePorts ({len(allowed)} ports): {sorted(allowed)}")
    if not allowed:
        return {"findings": [], "count": 0}
    findings = []
    try:
        for ns in namespaces:
            for svc in v1.list_namespaced_service(namespace=ns).items:
                if svc.spec.type != "NodePort":
                    continue
                for port in (svc.spec.ports or []):
                    if port.node_port and port.node_port not in allowed:
                        findings.append({
                            "namespace": ns,
                            "service": svc.metadata.name,
                            "node_port": port.node_port,
                            "severity": "HIGH",
                            "reason": f"NodePort {port.node_port} hors liste blanche",
                        })
    except ApiException as e:
        log.error(f"[nodeports] {e}")
        SCAN_ERRORS.labels(check_type="nodeports").inc()
    return {"findings": findings, "count": len(findings)}


def check_privileged_serviceaccounts(rbac: client.RbacAuthorizationV1Api) -> dict:
    findings = []
    dangerous = {"cluster-admin", "admin", "edit"}
    try:
        for crb in rbac.list_cluster_role_binding().items:
            if crb.role_ref.name not in dangerous:
                continue
            for subject in (crb.subjects or []):
                if subject.kind == "ServiceAccount":
                    findings.append({
                        "namespace": subject.namespace or "cluster-wide",
                        "serviceaccount": subject.name,
                        "role": crb.role_ref.name,
                        "binding": crb.metadata.name,
                        "severity": "CRITICAL" if crb.role_ref.name == "cluster-admin" else "HIGH",
                        "reason": f"SA lié à {crb.role_ref.name}",
                    })
    except ApiException as e:
        log.error(f"[serviceaccounts] {e}")
        SCAN_ERRORS.labels(check_type="serviceaccounts").inc()
    return {"findings": findings, "count": len(findings)}


def compute_risk_score(results: dict) -> int:
    weights = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4}
    score = sum(
        weights.get(f.get("severity", "HIGH"), 4)
        for r in results.values()
        for f in r["findings"]
    )
    return min(score, 100)


def run_scan() -> None:
    t_start = time.time()
    log.info("🔍 Scan sécurité démarré...")

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    v1         = client.CoreV1Api()
    networking = client.NetworkingV1Api()
    rbac       = client.RbacAuthorizationV1Api()

    namespaces = get_namespaces(v1)
    log.info(f"   Namespaces: {namespaces}")

    results = {
        "root_containers":   check_root_containers(v1, namespaces),
        "network_policies":  check_network_policies(v1, networking, namespaces),
        "exposed_secrets":   check_exposed_secrets(v1, namespaces),
        "exposed_nodeports": check_exposed_nodeports(v1, namespaces),
        "privileged_sa":     check_privileged_serviceaccounts(rbac),
    }

    ROOT_CONTAINERS.set(results["root_containers"]["count"])
    MISSING_NETPOL.set(results["network_policies"]["count"])
    EXPOSED_SECRETS.set(results["exposed_secrets"]["count"])
    EXPOSED_NODEPORT.set(results["exposed_nodeports"]["count"])
    PRIVILEGED_SA.set(results["privileged_sa"]["count"])

    score = compute_risk_score(results)
    RISK_SCORE.set(score)
    SCAN_DURATION.set(time.time() - t_start)

    total = sum(r["count"] for r in results.values())
    emoji = "🔴" if score >= 80 else "🟡" if score >= 50 else "🟢"
    log.info(f"{emoji} Score: {score}/100 | Findings: {total} | Durée: {time.time() - t_start:.1f}s")
    for name, result in results.items():
        if result["count"]:
            log.warning(f"   ⚠️  {name}: {result['count']} finding(s)")
            for f in result["findings"][:3]:
                log.warning(f"      → {f}")


if __name__ == "__main__":
    log.info(f"🚀 Security Scanner démarré — métriques sur :8000 — scan toutes les {SCAN_INTERVAL}s")
    start_http_server(8000)
    while True:
        run_scan()
        time.sleep(SCAN_INTERVAL)
