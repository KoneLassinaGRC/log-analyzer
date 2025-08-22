# Fichier de log : linux_auth.log

## Objectif
Ce fichier contient des logs simulés du service SSH d’un serveur Linux.  
Il est utilisé pour tester le script `analyzer.py` qui analyse les tentatives de connexion réussies et échouées.

## Structure des lignes
Chaque ligne contient :
- Date et heure du log
- Nom du serveur
- Service qui génère le log (sshd)
- PID du processus
- Type d’événement (Accepted password / Failed password)
- Nom d’utilisateur
- Adresse IP de la connexion
- Port utilisé
- Protocole (ssh2)

### Exemple
Aug 21 10:20:11 server sshd[12346]: Failed password for root from 192.168.1.25 port 56432 ssh2
## Points importants
- `Failed password` → tentative de connexion échouée
- `Accepted password` → connexion réussie
- L’analyse se concentre sur les utilisateurs et les adresses IP suspectes
