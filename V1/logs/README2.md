Log Analyzer - Analyseur de logs de sécurité

Version : 2.0.0
Auteur : Kone Lassina
Langage : Python 3
Licence : MIT (ou autre selon choix)

Description

Ce projet est un analyseur de logs de sécurité conçu pour détecter des intrusions, des tentatives de force brute, des connexions suspectes et d’autres anomalies dans des fichiers de logs serveur.
Il supporte différents types de logs tels que :

SSH (connexion réussie/échouée, utilisateur invalide)

Apache et Nginx (erreurs 404, échec d’authentification)

FTP (échec de login)

Le projet est modulaire et extensible : on peut facilement ajouter de nouveaux patterns de détection.

Fonctionnement général

Chargement des configurations depuis un fichier config.json.

Chargement des patterns de logs prédéfinis via PatternManager.

Analyse des fichiers logs situés dans un dossier défini (logs/ par défaut).

Détection des événements en comparant chaque ligne à tous les patterns connus.

Génération d’un rapport au format HTML, JSON ou TXT.

Affichage d’un résumé dans la console avec les IP suspectes, les tentatives échouées et les recommandations de sécurité.

Fonctionnalités principales

Détection de tentatives de login SSH échouées et réussies.

Détection d’utilisateurs invalides et d’attaques par force brute.

Analyse des logs Apache, Nginx et FTP pour erreurs et tentatives d’accès non autorisées.

Géolocalisation des IPs (optionnelle).

Support de différents formats de sortie : html, json, txt.

Mode test pour vérifier les patterns de logs avec des exemples.