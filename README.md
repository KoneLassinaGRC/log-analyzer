# Analyse de logs système pour détection d’incidents

## Objectif du projet
Ce projet permet d’analyser des fichiers de logs (Linux et Windows) pour détecter :
- Les tentatives de connexion échouées
- Les connexions suspectes
- Les adresses IP potentiellement malveillantes

Il a été réalisé dans le cadre de ma formation en cybersécurité et GRC à l’Orange Digital Academy.

---

## Structure du projet

log-analyzer/
├── analyzer.py # Script Python pour analyser les logs
├── README.md # Ce README principal
├── logs/ # Dossier contenant les fichiers de logs
│ ├── linux_auth.log
│ ├── windows_security.log
│ ├── README_linux.md
│ └── README_windows.md
├── rapport.txt # Exemple de rapport généré par le script
└── requirements.txt # Librairies Python nécessaires


---

## Fichiers de logs

- `logs/linux_auth.log` → Logs simulés SSH Linux  
  Voir le détail de la structure : [`README_linux.md`](logs/README_linux.md)

- `logs/windows_security.log` → Logs simulés Windows Security  
  Voir le détail de la structure : [`README_windows.md`](logs/README_windows.md)

---

## Utilisation

1. Placer les fichiers de logs dans le dossier `logs/`  
2. Exécuter le script `analyzer.py` avec Python 3  
```bash
python analyzer.py
