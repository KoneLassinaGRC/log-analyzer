# Fichier de log : windows_security.log

## Objectif
Ce fichier contient des logs simulés du journal de sécurité Windows.  
Il est utilisé pour tester le script `analyzer.py` pour détecter les connexions réussies et les échecs.

## Structure des lignes
Chaque ligne contient :
- Date et heure de l’événement
- Nom de l’utilisateur
- Type d’événement (login ou Failed login attempt)
- Adresse IP source

### Exemple
2025-08-21 10:20:11 Failed login attempt for user Administrator from 192.168.1.25
## Points importants
- `Failed login attempt` → tentative de connexion échouée
- `User <nom>` → connexion réussie
- L’analyse se concentre sur les utilisateurs et les adresses IP suspectes
