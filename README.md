# 🛠️ Log Analyzer  

## 📌 Description  
**Log Analyzer** est un outil d’analyse de journaux système (logs) qui permet de :  
- Détecter les erreurs critiques  
- Identifier des tentatives d’accès non autorisées  
- Rechercher des schémas d’attaques courants  
- Générer des rapports d’analyse exploitables  

Ce dépôt contient **deux versions distinctes** de l’outil :  
- **V1** : première version fonctionnelle, simple et basique  
- **V2** : version améliorée, plus robuste et mieux structurée  

---

## 📂 Structure du projet  
log-analyzer/
├── V1/ → Première version de base 
├── V2/ → Version améliorée 
└── README.md (ce fichier)


🔄 Différences entre V1 et V2

Fonctionnalité	V1 (basique) ✅	V2 (améliorée) 🚀
Détection d’erreurs	Oui (simple)	Oui (plus complète et précise)
Gestion des patterns	Limitée (quelques cas)	Avancée (plusieurs motifs + regex)
Génération de rapports	Texte brut	Texte + Markdown / HTML lisibles
Organisation du code	Fichiers uniques	Code modulé en plusieurs fichiers (config.py, report.py, etc.)
Gestion des erreurs	Basique	Plus robuste avec try/except
Géolocalisation des adresses IP	Non	Oui, avec un module geolocation.py
Documentation	Minimale	README détaillé et structuré
Extensibilité	Faible	Code plus flexible et maintenable
✨ Améliorations apportées dans la Version 2

La version 2 a été repensée pour être plus professionnelle, plus claire et plus modulaire. Voici les principales améliorations :

🧱 1. Architecture modulaire

Le code est séparé en plusieurs fichiers selon leur rôle :

config.py → paramètres globaux

log_analyzer.py → logique principale

patterns.py → motifs d’attaques (regex, mots-clés)

report.py → génération de rapports

geolocation.py → analyse des IP et localisation

Cela rend le code plus lisible, maintenable et évolutif.

🔍 2. Détection avancée

Plus de patterns de détection : attaques par brute-force, erreurs système, accès refusés, etc.

Utilisation d’expressions régulières (regex) pour identifier des anomalies précises.

Filtrage plus fin des événements intéressants.

📊 3. Rapports plus professionnels

Génération de rapports :

en texte brut

en Markdown (lisible sur GitHub)

ou en HTML (présentation claire pour les utilisateurs)

Résumé clair des erreurs détectées et des IP suspectes.

🌍 4. Analyse réseau / IP

Un nouveau module geolocation.py permet de :

extraire les adresses IP

localiser les IP (ex : pays d’origine)

repérer les connexions suspectes venant de l’étranger

🛡️ 5. Gestion d’erreurs améliorée

Utilisation de try/except pour éviter que le programme plante.

Messages d’erreurs clairs et compréhensibles.

Vérification de l’existence des fichiers d’entrée.

📘 6. Documentation complète

Un README.md bien structuré explique :

comment installer

comment exécuter

comment comprendre les résultats

Idéal pour partager le projet sur GitHub ou dans un portfolio.

🎯 En résumé, la version 2 n’est pas seulement une mise à jour : c’est une refonte complète de l’outil, avec une meilleure architecture, plus de détection, plus de clarté, et une approche plus professionnelle.

## ⚙️ Installation  
Clonez le dépôt depuis GitHub :  

```bash
git clone https://github.com/KoneLassinaGRC/log-analyzer.git

cd log-analyzer
cd V1   # Pour la version 1
# ou
cd V2   # Pour la version 2
▶️ Utilisation ( V2)
python log_analyzer.py --input chemin/vers/logfile.log --output rapport.txt

📌 Auteur

👤 Kone Lassina
Étudiant en cybersécurité soc, spécialisé en Gouvernance, Risques et Conformité (GRC).