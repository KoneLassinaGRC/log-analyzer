Analyseur de Logs de Sécurité
Description

Ce projet est un analyseur de logs de sécurité destiné à détecter des intrusions, des tentatives de connexion suspectes et d’autres anomalies dans les serveurs SSH, Apache, Nginx et FTP.
Il parse des fichiers logs, identifie des patterns spécifiques et génère des rapports détaillés en HTML, JSON ou TXT.

Fonctionnalités

Détection des tentatives de connexion SSH échouées ou réussies

Détection des utilisateurs invalides sur SSH

Analyse des erreurs Apache et Nginx (404, 401…)

Détection des échecs de login FTP

Génération de rapports détaillés avec statistiques

Mode test pour vérifier les patterns sur des logs d’exemple

Support de la géolocalisation des IPs (optionnel)

Personnalisation des seuils et de la fenêtre temporelle

Arborescence du projet
log-analyzer/
├─ core/
│  ├─ main.py                 # Script principal
│  ├─ log_analyzer.py         # Analyseur et gestion de la configuration
│  ├─ patterns.py             # Définition des patterns de logs
│  ├─ geolocation.py          # Service de géolocalisation (optionnel)
├─ logs/
│  ├─ ssh_logs.txt            # Logs SSH d'exemple
│  ├─ apache_logs.txt         # Logs Apache d'exemple
│  ├─ nginx_logs.txt          # Logs Nginx d'exemple
│  ├─ ftp_logs.txt            # Logs FTP d'exemple
├─ config.json                # Configuration par défaut
├─ README.md                  # Documentation du projet
└─ requirements.txt           # Librairies Python nécessaires
