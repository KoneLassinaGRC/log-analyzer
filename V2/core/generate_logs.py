#!/usr/bin/env python3
"""
Générateur de logs d'exemple pour tester l'analyseur de sécurité
"""

import random
from datetime import datetime, timedelta
from pathlib import Path


class LogGenerator:
    """Générateur de logs d'exemple réalistes"""

    def __init__(self):
        # IPs d'attaquants simulés
        self.attacker_ips = [
            "203.0.113.42",   # Attaque par force brute
            "198.51.100.123", # Scan de reconnaissance
            "192.0.2.99",     # Attaque ciblée
            "185.220.100.240", # IP Tor
            "45.142.212.61",  # IP suspecte
        ]

        # IPs légitimes
        self.legitimate_ips = [
            "10.0.0.50",      # Réseau interne
            "192.168.1.100",  # Réseau local
            "172.16.0.25",    # Réseau privé
        ]

        # Utilisateurs légitimes
        self.legitimate_users = ["alice", "bob", "charlie", "david", "emma"]

        # Utilisateurs suspects/ciblés
        self.target_users = ["admin", "root", "administrator", "test", "guest"]

        # Agents utilisateur
        self.user_agents = [
            "OpenSSH_8.0",
            "libssh_0.6.3",
            "PuTTY_Release_0.76",
            "Mozilla/5.0 (compatible; scanner)"
        ]

    # -------------------
    # Générateurs de logs
    # -------------------

    def generate_ssh_logs(self, filename: str, num_entries: int = 200):
        """Génère des logs SSH simulés"""
        print(f"Génération de {num_entries} entrées SSH dans {filename}...")
        log_entries = []
        base_time = datetime.now() - timedelta(days=3)

        for _ in range(num_entries):
            current_time = base_time + timedelta(minutes=random.randint(1, 10))
            timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")

            if random.random() < 0.4:  # 40% échecs
                ip = random.choice(self.attacker_ips + self.legitimate_ips)
                user = random.choice(self.target_users + self.legitimate_users)
                entry = f"{timestamp} SSH LOGIN FAILED: User={user} IP={ip}"
            else:
                ip = random.choice(self.legitimate_ips)
                user = random.choice(self.legitimate_users)
                entry = f"{timestamp} SSH LOGIN SUCCESS: User={user} IP={ip}"

            log_entries.append(entry)
            base_time = current_time

        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with open(filename, "w") as f:
            f.write("\n".join(log_entries))

    def generate_apache_logs(self, filename: str, num_entries: int = 200):
        """Génère des logs Apache simulés"""
        print(f"Génération de {num_entries} entrées Apache dans {filename}...")
        log_entries = []
        base_time = datetime.now() - timedelta(days=2)

        for _ in range(num_entries):
            current_time = base_time + timedelta(seconds=random.randint(5, 60))
            timestamp = current_time.strftime("%d/%b/%Y:%H:%M:%S")
            ip = random.choice(self.attacker_ips + self.legitimate_ips)
            user = random.choice(["-", random.choice(self.legitimate_users)])
            method = random.choice(["GET", "POST", "DELETE"])
            resource = random.choice(["/index.html", "/login", "/admin", "/upload"])
            code = random.choice([200, 302, 403, 404, 500])
            size = random.randint(200, 5000)

            entry = f'{ip} - {user} [{timestamp} +0000] "{method} {resource} HTTP/1.1" {code} {size}'
            log_entries.append(entry)
            base_time = current_time

        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with open(filename, "w") as f:
            f.write("\n".join(log_entries))

    def generate_windows_logs(self, filename: str, num_entries: int = 200):
        """Génère des logs Windows simulés"""
        print(f"Génération de {num_entries} entrées Windows dans {filename}...")
        log_entries = []
        base_time = datetime.now() - timedelta(days=1)

        for _ in range(num_entries):
            current_time = base_time + timedelta(minutes=random.randint(1, 30))
            timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
            user = random.choice(self.legitimate_users + self.target_users)
            event_id = random.choice([4624, 4625, 4648, 4688])
            status = "SUCCESS" if event_id in [4624, 4688] else "FAILED"
            ip = random.choice(self.attacker_ips + self.legitimate_ips)

            entry = f"{timestamp} EVENT_ID={event_id} User={user} Status={status} SourceIP={ip}"
            log_entries.append(entry)
            base_time = current_time

        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with open(filename, "w") as f:
            f.write("\n".join(log_entries))

    def generate_ftp_logs(self, filename: str, num_entries: int = 200):
        """Génère des logs FTP simulés"""
        print(f"Génération de {num_entries} entrées FTP dans {filename}...")
        log_entries = []
        base_time = datetime.now() - timedelta(days=3)

        for _ in range(num_entries):
            current_time = base_time + timedelta(minutes=random.randint(2, 20))
            timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")

            if random.random() < 0.3:  # 30% échecs
                ip = random.choice(self.attacker_ips + self.legitimate_ips)
                user = random.choice(self.target_users + self.legitimate_users)
                entry = f"{timestamp} FTP LOGIN FAILED: User={user} IP={ip}"
            else:  # 70% succès
                ip = random.choice(self.legitimate_ips)
                user = random.choice(self.legitimate_users)
                action = random.choice(["UPLOAD file.txt", "DOWNLOAD report.pdf", "LIST directory", "DELETE temp.log"])
                entry = f"{timestamp} FTP LOGIN SUCCESS: User={user} IP={ip} - Action: {action}"

            log_entries.append(entry)
            base_time = current_time

        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with open(filename, "w") as f:
            f.write("\n".join(log_entries))

    # -------------------
    # Générateur global
    # -------------------

    def generate_all_logs(self, output_dir: str):
        """Génère tous les types de logs dans un dossier"""
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)

        self.generate_ssh_logs(output / "ssh.log")
        self.generate_apache_logs(output / "apache.log")
        self.generate_windows_logs(output / "windows.log")
        self.generate_ftp_logs(output / "ftp.log")

        print(f"\n✅ Tous les fichiers de logs ont été générés dans {output_dir}/")


if __name__ == "__main__":
    generator = LogGenerator()
    generator.generate_all_logs("logs_exemple")
