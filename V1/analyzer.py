import os
from collections import defaultdict
from datetime import datetime

# Dossier contenant les logs
LOG_DIR = "logs"

# Nom du fichier de sortie
REPORT_FILE = "rapport.txt"

def analyze_linux_log(file_path):
    failed = defaultdict(list)
    success = defaultdict(list)
    
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Exemple : "Aug 21 10:20:11 server sshd[12346]: Failed password for root from 192.168.1.25 port 56432 ssh2"
            if "Failed password for" in line:
                parts = line.split()
                user = parts[8]
                ip = parts[10]
                failed[user].append(ip)
            elif "Accepted password for" in line:
                parts = line.split()
                user = parts[8]
                ip = parts[10]
                success[user].append(ip)
    return failed, success

def analyze_windows_log(file_path):
    failed = defaultdict(list)
    success = defaultdict(list)
    
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Exemple : "2025-08-21 10:20:11 Failed login attempt for user Administrator from 192.168.1.25"
            if "Failed login attempt for user" in line:
                parts = line.split()
                user = parts[5]
                ip = parts[-1]
                failed[user].append(ip)
            elif "User" in line and "logged on" in line:
                parts = line.split()
                user = parts[1]
                ip = parts[-1]
                success[user].append(ip)
    return failed, success

def write_report(reports):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(REPORT_FILE, "w") as f:
        f.write("="*30 + "\n")
        f.write("Rapport d'analyse des logs\n")
        f.write("="*30 + "\n\n")
        f.write(f"Date de génération : {now}\n\n")
        
        total_failed = 0
        total_success = 0
        ip_suspectes = set()
        
        for log_name, (failed, success) in reports.items():
            f.write(f"Fichier analysé : {log_name}\n\n")
            
            f.write("Tentatives de connexion échouées :\n")
            for user, ips in failed.items():
                f.write(f"- {user} : {len(ips)} tentatives (IP : {', '.join(set(ips))})\n")
                total_failed += len(ips)
                ip_suspectes.update(ips)
            
            f.write("\nConnexions réussies :\n")
            for user, ips in success.items():
                f.write(f"- {user} : {len(ips)} connexions (IP : {', '.join(set(ips))})\n")
                total_success += len(ips)
            
            f.write("\n---\n\n")
        
        f.write("Résumé global :\n")
        f.write(f"- Nombre total de tentatives échouées : {total_failed}\n")
        f.write(f"- Nombre total de connexions réussies : {total_success}\n")
        f.write(f"- IP suspectes : {', '.join(ip_suspectes)}\n\n")
        f.write("="*30 + "\n")
        f.write("Fin du rapport\n")
        f.write("="*30 + "\n")

def main():
    reports = {}
    
    for file_name in os.listdir(LOG_DIR):
        file_path = os.path.join(LOG_DIR, file_name)
        if not os.path.isfile(file_path):
            continue
        if "linux" in file_name.lower():
            reports[file_name] = analyze_linux_log(file_path)
        elif "windows" in file_name.lower():
            reports[file_name] = analyze_windows_log(file_path)
    
    write_report(reports)
    print(f"Rapport généré : {REPORT_FILE}")

if __name__ == "__main__":
    main()
