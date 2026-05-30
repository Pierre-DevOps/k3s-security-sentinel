#!/usr/bin/env python3
"""
AI Security Sentinel — Security Scanner
Détecte les failles K8s et expose des métriques Prometheus
Pierre-DevOps | pierre.devops08@gmail.com
"""

import time
import logging
from prometheus_client import start_http_server, Gauge, Counter
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("security-sentinel")

# ─── Métriques Prometheus ──────────────────────────────────────────────────────
RISK_SCORE = Gauge(
    "security_risk_score",
    "Score de risque sécurité global du cluster (0-100)",
)
FINDING_COUNT = Gauge(
    "security_findings_total",
    "Nombre de failles détectées",
    ["severity", "check_type"],
)
ROOT_CONTAINERS = Gauge(
    "security_root_containers_total",
    "Containers tournant en root (UID 0 ou runAsNonRoot absent)",
)
MISSING_NETPOL = Gauge(
    "security_missing_networkpolicy_total",
    "Namespaces sans NetworkPolicy",
)
EXPOSED_SECRETS = Gauge(
    "security_exposed_secrets_total",
    "Secrets avec valeurs en clair dans les env vars",
)
PRIVILEGED_SA = Gauge(
    "security_privileged_serviceaccounts_total",
    "ServiceAccounts avec clusterrolebinding admin/cluster-admin",
)
EXPOSED_NODEPORTS = Gauge(
    "security_exposed_nodeports_total",
    "Services NodePort hors liste blanche",
)
SCAN_DURATION = Gauge(
    "security_scan_duration_seconds",
    "Durée du dernier scan en secondes",
)
SCAN_ERRORS = Counter(
    "security_scan_errors_total",
    "Erreurs de scan",
    ["check_type"],
)

# ─── Namespaces exclus du scope ────────────────────────────────────────────────
EXCLUDED_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}

# ─── NodePorts autorisés (adapte selon ton cluster) ───────────────────────────
ALLOWED_NODEPORTS = {
    31701, 31702, 31703, 31704,  # AutoVoxPro / ImmoRelance / AvisFlow
    30500, 30900,                 # azure-cost-calculator / Zabbix
    30300, 30301,                 # ArtisanFlow
    31760,                        # CrècheAir
    5678,                         # n8n
}

# ─── Mots-clés suspects dans les noms de variables d'environnement ─────────────
SECRET_KEYWORDS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "auth", "credential", "private_key", "access_key", "db_pass",
    "jwt", "bearer",
}


def get_namespaces(v1: client.CoreV1Api) -> list[str]:
    """Retourne tous les namespaces hors exclusions."""
    try:
        ns_list = v1.list_namespace()
        return [
            ns.metadata.name
            for ns in ns_list.items
            if ns.metadata.name not in EXCLUDED_NAMESPACES
        ]
    except ApiException as e:
        log.error(f"[namespaces] {e}")
        SCAN_ERRORS.labels(check_type="list_namespaces").inc()
        return []


def check_root_containers(v1: client.CoreV1Api, namespaces: list[str]) -> dict:
    """Détecte les containers sans runAsNonRoot ou avec runAsUser=0."""
    findings = []
    try:
        for ns in namespaces:
            pods = v1.list_namespaced_pod(namespace=ns)
            for pod in pods.items:
                spec = pod.spec
                pod_sc = spec.security_context or client.V1PodSecurityContext()
                for container in spec.containers + (spec.init_containers or []):
                    c_sc = container.security_context or client.V1SecurityContext()
                    is_root = False
                    reason = ""
                    # runAsNonRoot explicitement false ou absent
                    if c_sc.run_as_non_root is False:
                        is_root = True
                        reason = "runAsNonRoot: false"
                    elif c_sc.run_as_non_root is None and pod_sc.run_as_non_root is not True:
                        # pas de protection côté pod non plus
                        if c_sc.run_as_user == 0 or pod_sc.run_as_user == 0:
                            is_root = True
                            reason = "runAsUser: 0"
                        elif c_sc.run_as_non_root is None and pod_sc.run_as_non_root is None:
                            # aucune contrainte → probablement root par défaut de l'image
                            is_root = True
                            reason = "runAsNonRoot absent"
                    if is_root:
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


def check_network_policies(v1: client.CoreV1Api, networking: client.NetworkingV1Api, namespaces: list[str]) -> dict:
    """Namespaces sans aucune NetworkPolicy."""
    findings = []
    try:
        for ns in namespaces:
            pods = v1.list_namespaced_pod(namespace=ns)
            if not pods.items:
                continue  # namespace vide, on ignore
            netpols = networking.list_namespaced_network_policy(namespace=ns)
            if not netpols.items:
                pod_count = len(pods.items)
                findings.append({
                    "namespace": ns,
                    "pod_count": pod_count,
                    "severity": "CRITICAL",
                    "reason": f"{pod_count} pods sans NetworkPolicy",
                })
    except ApiException as e:
        log.error(f"[network_policies] {e}")
        SCAN_ERRORS.labels(check_type="network_policies").inc()
    return {"findings": findings, "count": len(findings)}


def check_exposed_secrets(v1: client.CoreV1Api, namespaces: list[str]) -> dict:
    """Détecte les secrets/mots de passe dans les env vars des pods (en clair)."""
    findings = []
    try:
        for ns in namespaces:
            pods = v1.list_namespaced_pod(namespace=ns)
            for pod in pods.items:
                for container in pod.spec.containers:
                    if not container.env:
                        continue
                    for env_var in container.env:
                        name_lower = env_var.name.lower()
                        if any(kw in name_lower for kw in SECRET_KEYWORDS):
                            # Valeur en clair = value présent, pas valueFrom
                            if env_var.value and not env_var.value_from:
                                findings.append({
                                    "namespace": ns,
                                    "pod": pod.metadata.name,
                                    "container": container.name,
                                    "env_var": env_var.name,
                                    "severity": "CRITICAL",
                                    "reason": "Secret en clair dans env var",
                                })
    except ApiException as e:
        log.error(f"[exposed_secrets] {e}")
        SCAN_ERRORS.labels(check_type="exposed_secrets").inc()
    return {"findings": findings, "count": len(findings)}


def check_exposed_nodeports(v1: client.CoreV1Api, namespaces: list[str]) -> dict:
    """Services NodePort hors liste blanche."""
    findings = []
    try:
        for ns in namespaces:
            services = v1.list_namespaced_service(namespace=ns)
            for svc in services.items:
                if svc.spec.type != "NodePort":
                    continue
                for port in (svc.spec.ports or []):
                    if port.node_port and port.node_port not in ALLOWED_NODEPORTS:
                        findings.append({
                            "namespace": ns,
                            "service": svc.metadata.name,
                            "node_port": port.node_port,
                            "severity": "HIGH",
                            "reason": f"NodePort {port.node_port} non autorisé",
                        })
    except ApiException as e:
        log.error(f"[nodeports] {e}")
        SCAN_ERRORS.labels(check_type="nodeports").inc()
    return {"findings": findings, "count": len(findings)}


def check_privileged_serviceaccounts(rbac: client.RbacAuthorizationV1Api) -> dict:
    """ClusterRoleBindings donnant cluster-admin ou admin à un ServiceAccount."""
    findings = []
    dangerous_roles = {"cluster-admin", "admin", "edit"}
    try:
        crbs = rbac.list_cluster_role_binding()
        for crb in crbs.items:
            if crb.role_ref.name not in dangerous_roles:
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
    """
    Score 0-100 basé sur la criticité et le nombre de findings.
    CRITICAL = 15 pts, HIGH = 8 pts, plafonné à 100.
    """
    score = 0
    weights = {"CRITICAL": 15, "HIGH": 8}
    for check_name, check_result in results.items():
        for finding in check_result["findings"]:
            sev = finding.get("severity", "HIGH")
            score += weights.get(sev, 5)
    return min(score, 100)


def run_scan() -> None:
    """Exécute un cycle complet de scan et met à jour les métriques Prometheus."""
    t_start = time.time()
    log.info("🔍 Démarrage du scan sécurité...")

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    v1 = client.CoreV1Api()
    networking = client.NetworkingV1Api()
    rbac = client.RbacAuthorizationV1Api()

    namespaces = get_namespaces(v1)
    log.info(f"   Namespaces scannés: {namespaces}")

    results = {
        "root_containers":     check_root_containers(v1, namespaces),
        "network_policies":    check_network_policies(v1, networking, namespaces),
        "exposed_secrets":     check_exposed_secrets(v1, namespaces),
        "exposed_nodeports":   check_exposed_nodeports(v1, namespaces),
        "privileged_sa":       check_privileged_serviceaccounts(rbac),
    }

    # ── Mise à jour des métriques ──────────────────────────────────────────────
    ROOT_CONTAINERS.set(results["root_containers"]["count"])
    MISSING_NETPOL.set(results["network_policies"]["count"])
    EXPOSED_SECRETS.set(results["exposed_secrets"]["count"])
    EXPOSED_NODEPORTS.set(results["exposed_nodeports"]["count"])
    PRIVILEGED_SA.set(results["privileged_sa"]["count"])

    for check_name, check_result in results.items():
        by_severity = {}
        for f in check_result["findings"]:
            sev = f.get("severity", "HIGH")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        for sev, count in by_severity.items():
            FINDING_COUNT.labels(severity=sev, check_type=check_name).set(count)

    score = compute_risk_score(results)
    RISK_SCORE.set(score)

    t_elapsed = time.time() - t_start
    SCAN_DURATION.set(t_elapsed)

    # ── Résumé console ────────────────────────────────────────────────────────
    total = sum(r["count"] for r in results.values())
    log.info(f"✅ Scan terminé en {t_elapsed:.1f}s | Score risque: {score}/100 | Findings: {total}")
    for check_name, check_result in results.items():
        if check_result["count"] > 0:
            log.warning(f"   ⚠️  {check_name}: {check_result['count']} finding(s)")
            for f in check_result["findings"][:3]:  # max 3 en console
                log.warning(f"      → {f}")


if __name__ == "__main__":
    log.info("🚀 AI Security Sentinel démarré — port métriques: 8000")
    start_http_server(8000)
    SCAN_INTERVAL = 300  # 5 minutes
    while True:
        run_scan()
        log.info(f"⏳ Prochain scan dans {SCAN_INTERVAL}s...")
        time.sleep(SCAN_INTERVAL)
