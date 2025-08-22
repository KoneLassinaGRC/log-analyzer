# Log Analyzer - Version 2 🚀

## 📌 Description
Cette deuxième version de **Log Analyzer** améliore la première (V1) avec de nouvelles fonctionnalités, une meilleure organisation du code et une documentation plus claire.

Le but de l’outil est d’analyser des fichiers de logs afin de détecter rapidement :
- Les erreurs critiques
- Les tentatives d’accès suspectes
- Les schémas récurrents d’attaques

---

## ✨ Nouveautés par rapport à V1
- ✅ Code réorganisé en modules (`config.py`, `log_analyzer.py`, `report.py`, etc.)
- ✅ Ajout de nouveaux patterns dans `patterns.py`
- ✅ Rapport d’analyse amélioré (généré en Markdown ou HTML)
- ✅ Gestion d’erreurs plus robuste
- ✅ Documentation enrichie

---

## ⚙️ Installation
Clonez le dépôt puis placez-vous dans le dossier `V2` :

```bash
git clone https://github.com/KoneLassinaGRC/log-analyzer.git
cd log-analyzer/V2
▶️ Utilisation

Exécutez le script principal pour analyser vos logs :

python log_analyzer.py --input chemin/vers/logfile.log --output rapport.txt


Options disponibles :

--input : chemin vers le fichier log à analyser

--output : fichier où sera enregistré le rapport
📂 Structure du projet
V2/
 ├── config.py         # Configuration générale
 ├── geolocation.py    # Gestion des adresses IP et géolocalisation
 ├── log_analyzer.py   # Script principal
 ├── patterns.py       # Détection des motifs d’attaques
 ├── report.py         # Génération des rapports
 └── README.md         # Documentation (ce fichier)

📊 Exemple de sortie
[INFO] Analyse du fichier system.log...
[WARNING] Tentative d'accès non autorisée détectée (IP: 192.168.1.50)
[ERROR] Erreur critique dans le service Apache
Rapport généré : rapport.txt

📌 Auteur

Kone Lassina – Étudiant en cybersécurité SOC 

