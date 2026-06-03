# AI Security Sentinel

Agent de surveillance securite temps reel pour clusters Kubernetes.

Scanner Python toutes les 5 minutes → scoring 0-100 → Alertmanager → n8n → Groq LLaMA 3.3 70B → Pull Request GitHub automatique → email Brevo.

## Resultats en production

- Score de risque : 100 → 52 (-48%)
- Findings : 31 → 13 (-58%)
- Secrets exposes : 3 → 0
- MTTR Secrets exposes : 2h48
- MTTR NetworkPolicy manquantes : 14h49
- MTTR moyen global : 8h49

## Pipeline

Scanner Python → Prometheus → Alertmanager → n8n → Groq LLaMA 3.3 70B → GitHub PR → Brevo email

## 6 phases

- Phase 1 - Detecter : scanner Python, scoring Prometheus
- Phase 2 - Analyser et corriger : n8n, Groq, PR GitHub automatique
- Phase 3 - Visualiser : dashboard Grafana edition technique et edition RSSI
- Phase 4 - Historiser : PostgreSQL, scan toutes les 5 min, retention 30 jours
- Phase 5 - Mesurer : MTTR par type de finding, metriques Prometheus
- Phase 6 - Presenter : rapport hebdomadaire, indicateurs decisionnels direction

## Stack technique

Python, Prometheus, Alertmanager, Grafana, n8n, Groq LLaMA 3.3 70B, PostgreSQL, GitHub API, Brevo, K3s, ArgoCD

## Documentation complete

https://pierre-devops.com/projets/ai-security-sentinel.html
