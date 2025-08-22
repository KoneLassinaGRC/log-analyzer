"""
Module d'analyse de sécurité pour la détection d'attaques et anomalies
"""

import logging
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Set, Tuple, Optional, Any
import statistics
import re


class SecurityAnalyzer:
    """Analyseur de sécurité pour détecter les menaces et anomalies"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Seuils configurables
        self.bruteforce_threshold: int = int(config.get("bruteforce_threshold", 5))
        self.time_window_minutes: int = int(config.get("time_window_minutes", 60))
        self.suspicious_users: Set[str] = set(config.get("suspicious_users", []))

        # Seuils anti-bruit (peuvent être ajoutés au config.json si souhaité)
        self.multi_location_ip_threshold: int = int(
            config.get("multi_location_ip_threshold", 3)
        )
        # Regrouper les IPs par /24 pour IPv4, /64 pour IPv6
        self.multi_location_networks_threshold: int = int(
            config.get("multi_location_networks_threshold", 3)
        )

        # Patterns de détection (payloads)
        self.threat_patterns: Dict[str, List[str]] = {
            "sql_injection": [
                r"(?i)'\s*or\s*'",
                r"(?i)union\s+select",
                r"(?i)\bdrop\s+table\b",
                r"(?i)\binsert\s+into\b",
                r"(?i)\bdelete\s+from\b",
            ],
            "xss_attempts": [
                r"(?i)<\s*script\b",
                r"(?i)\bjavascript:",
                r"(?i)\bonload\s*=",
                r"(?i)\bonerror\s*=",
            ],
            "directory_traversal": [
                r"\.\./",
                r"\.\.\\",
                r"/etc/passwd",
                r"/proc/",
                r"\bboot\.ini\b",
            ],
        }

        # Compile regex patterns
        self.compiled_patterns: Dict[str, List[re.Pattern]] = {}
        for threat_type, patterns in self.threat_patterns.items():
            self.compiled_patterns[threat_type] = [
                re.compile(p) for p in patterns
            ]

    # ---------------------------
    # Détection brute force
    # ---------------------------
    def detect_bruteforce_attacks(
        self, failed_attempts: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Détecte les attaques par force brute basées sur les tentatives échouées

        Args:
            failed_attempts: Dictionnaire user -> liste des tentatives

        Returns:
            Dictionnaire des attaques détectées par IP
        """
        attacks: Dict[str, Dict[str, Any]] = {}

        # Grouper les tentatives par IP
        ip_attempts: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for user, attempts in failed_attempts.items():
            for attempt in attempts:
                ip = attempt.get("ip")
                if not ip:
                    continue
                ip_attempts[ip].append(
                    {
                        "user": user,
                        "timestamp": attempt.get("timestamp"),
                        "line_number": attempt.get("line_number"),
                    }
                )

        # Analyser chaque IP
        for ip, attempts in ip_attempts.items():
            attack_data = self._analyze_ip_attempts(ip, attempts)
            if attack_data and attack_data.get("is_attack"):
                attacks[ip] = attack_data

        return attacks

    def _analyze_ip_attempts(
        self, ip: str, attempts: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Analyse les tentatives d'une IP spécifique

        Args:
            ip: Adresse IP
            attempts: Liste des tentatives

        Returns:
            Données d'attaque ou None
        """
        total_attempts = len(attempts)
        if total_attempts < self.bruteforce_threshold:
            return None

        # Utilisateurs ciblés
        targeted_users = [a.get("user") for a in attempts if a.get("user")]
        unique_users: Set[str] = set(targeted_users)

        # Timestamps
        timestamps = [a.get("timestamp") for a in attempts if a.get("timestamp")]
        temporal_analysis = self._analyze_temporal_pattern(timestamps)

        # Score & typage
        threat_score = self._calculate_threat_score(
            ip, attempts, unique_users, temporal_analysis
        )
        attack_type = self._classify_attack_type(attempts, unique_users, temporal_analysis)

        return {
            "ip": ip,
            "is_attack": True,
            "attack_type": attack_type,
            "total_attempts": total_attempts,
            "unique_users_targeted": len(unique_users),
            "targeted_users": list(unique_users),
            "threat_score": threat_score,
            "temporal_analysis": temporal_analysis,
            "first_attempt": temporal_analysis.get("first_attempt"),
            "last_attempt": temporal_analysis.get("last_attempt"),
            "duration_minutes": temporal_analysis.get("duration_minutes", 0.0),
            "attempts_per_minute": temporal_analysis.get("attempts_per_minute", 0.0),
            "suspicious_users_targeted": [
                u for u in unique_users if u in self.suspicious_users
            ],
        }

    # ---------------------------
    # Analyse temporelle
    # ---------------------------
    def _parse_datetime_safe(self, ts: str) -> Optional[datetime]:
        """
        Essaie de parser un timestamp dans plusieurs formats courants, retourne un datetime naïf (local) ou UTC quand possible.
        Formats gérés :
          - 'YYYY-mm-dd HH:MM:SS'
          - 'YYYY-mm-ddTHH:MM:SS'
          - 'YYYY-mm-ddTHH:MM:SS.ssssssZ' / avec décalage
          - 'Aug 21 HH:MM:SS' (année courante injectée)
          - 'dd/Mon/YYYY:HH:MM:SS' (style Apache)
        """
        if not ts or not isinstance(ts, str):
            return None

        ts = ts.strip()
        year = datetime.now().year

        # 1) ISO-like avec timezone éventuelle
        try:
            # fromisoformat ne gère pas 'Z', on le remplace par '+00:00'
            iso = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso)
            # Retourner naïf (sans timezone) pour simplifier les calculs
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except Exception:
            pass

        # 2) Formats simples
        simple_formats = [
            "%Y-%m-%d %H:%M:%S",        # 2025-08-21 10:15:32
            "%Y-%m-%dT%H:%M:%S",        # 2025-08-21T10:15:32
            "%d/%b/%Y:%H:%M:%S",        # 21/Aug/2025:10:15:32
        ]
        for fmt in simple_formats:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue

        # 3) Syslog-like sans année: "Aug 21 10:15:32"
        try:
            dt = datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
            return dt
        except ValueError:
            pass

        # 4) Avec millisecondes éventuelles (ex: 2025-08-21 10:15:32.123)
        try:
            if "." in ts:
                # Essai avec millisecondes sans timezone
                for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f"):
                    try:
                        return datetime.strptime(ts, fmt)
                    except ValueError:
                        continue
        except Exception:
            pass

        self.logger.debug("Impossible de parser le timestamp: %s", ts)
        return None

    def _analyze_temporal_pattern(self, timestamps: List[str]) -> Dict[str, Any]:
        """
        Analyse les patterns temporels des tentatives

        Args:
            timestamps: Liste des timestamps

        Returns:
            Analyse temporelle
        """
        if not timestamps:
            return {}

        # Convertir les timestamps
        datetime_objects: List[datetime] = []
        for ts in timestamps:
            dt = self._parse_datetime_safe(ts)
            if dt:
                datetime_objects.append(dt)

        if not datetime_objects:
            return {}

        datetime_objects.sort()

        first_attempt_dt = datetime_objects[0]
        last_attempt_dt = datetime_objects[-1]
        duration = last_attempt_dt - first_attempt_dt

        # Intervalles entre les tentatives
        intervals: List[float] = []
        for i in range(1, len(datetime_objects)):
            interval = (datetime_objects[i] - datetime_objects[i - 1]).total_seconds()
            intervals.append(interval)

        duration_minutes = max(0.0, duration.total_seconds() / 60.0)
        attempts_per_minute = (
            len(datetime_objects) / duration_minutes if duration_minutes > 0 else float(len(datetime_objects))
        )

        analysis: Dict[str, Any] = {
            "first_attempt": first_attempt_dt.isoformat(sep=" "),
            "last_attempt": last_attempt_dt.isoformat(sep=" "),
            "duration_minutes": duration_minutes,
            "total_attempts": len(datetime_objects),
            "attempts_per_minute": attempts_per_minute,
        }

        if intervals:
            analysis.update(
                {
                    "avg_interval_seconds": statistics.mean(intervals),
                    "min_interval_seconds": min(intervals),
                    "max_interval_seconds": max(intervals),
                    "median_interval_seconds": statistics.median(intervals),
                    "rapid_fire_attempts": sum(1 for i in intervals if i < 5),  # < 5 secondes
                }
            )
        else:
            analysis["rapid_fire_attempts"] = 0

        return analysis

    def _calculate_threat_score(
        self,
        ip: str,
        attempts: List[Dict[str, Any]],
        unique_users: Set[str],
        temporal_analysis: Dict[str, Any],
    ) -> float:
        """
        Calcule un score de menace (0-100)
        """
        score = 0.0

        # Points basés sur le nombre de tentatives
        total_attempts = len(attempts)
        score += min(total_attempts * 2, 40)  # Max 40 points

        # Points pour les utilisateurs suspects ciblés
        suspicious_targeted = len([u for u in unique_users if u in self.suspicious_users])
        score += suspicious_targeted * 10  # 10 points par utilisateur suspect

        # Points pour la diversité des utilisateurs ciblés
        user_diversity = len(unique_users)
        if user_diversity > 5:
            score += 15
        elif user_diversity > 2:
            score += 10

        # Points pour les patterns temporels
        attempts_per_minute = float(temporal_analysis.get("attempts_per_minute", 0.0) or 0.0)
        if attempts_per_minute > 10:
            score += 20
        elif attempts_per_minute > 5:
            score += 10

        # Points pour les tentatives rapides
        rapid_fire = int(temporal_analysis.get("rapid_fire_attempts", 0) or 0)
        if rapid_fire > 0:
            score += min(rapid_fire * 2, 15)

        # Points pour IP externe (non privée)
        if not self._is_private_ip(ip):
            score += 5

        return min(score, 100.0)

    def _classify_attack_type(
        self,
        attempts: List[Dict[str, Any]],
        unique_users: Set[str],
        temporal_analysis: Dict[str, Any],
    ) -> str:
        """
        Classifie le type d'attaque
        """
        total_attempts = len(attempts)
        user_count = len(unique_users)
        attempts_per_minute = float(temporal_analysis.get("attempts_per_minute", 0.0) or 0.0)
        rapid_fire = int(temporal_analysis.get("rapid_fire_attempts", 0) or 0)

        # Attaque par dictionnaire (beaucoup d'utilisateurs différents)
        if user_count > 10 and user_count / max(1, total_attempts) > 0.5:
            return "dictionary_attack"

        # Attaque par force brute rapide
        if rapid_fire > total_attempts * 0.3 and attempts_per_minute > 5:
            return "rapid_bruteforce"

        # Attaque par force brute lente (pour éviter la détection)
        if attempts_per_minute < 2 and total_attempts > 20:
            return "slow_bruteforce"

        # Scan de reconnaissance (peu de tentatives par utilisateur)
        if user_count > 5 and total_attempts / max(1, user_count) < 3:
            return "reconnaissance_scan"

        # Attaque ciblée (peu d'utilisateurs, beaucoup de tentatives)
        if user_count <= 3 and total_attempts > 20:
            return "targeted_attack"

        return "bruteforce_attack"

    # ---------------------------
    # Détection d'anomalies
    # ---------------------------
    def detect_anomalies(
        self,
        successful_logins: Dict[str, List[Dict[str, Any]]],
        failed_attempts: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Détecte les anomalies dans les connexions
        """
        anomalies: Dict[str, List[Dict[str, Any]]] = {
            "unusual_login_times": [],
            "multiple_locations": [],
            "privilege_escalation": [],
            "account_takeover_indicators": [],
        }

        anomalies["unusual_login_times"] = self._detect_unusual_login_times(successful_logins)
        anomalies["multiple_locations"] = self._detect_multiple_locations(successful_logins)
        anomalies["account_takeover_indicators"] = self._detect_account_takeover(
            successful_logins, failed_attempts
        )

        return anomalies

    def _detect_unusual_login_times(
        self, successful_logins: Dict[str, List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """
        Détecte les connexions à des heures inhabituelles
        """
        anomalies: List[Dict[str, Any]] = []

        for user, logins in successful_logins.items():
            login_hours: List[int] = []

            for login in logins:
                timestamp = login.get("timestamp")
                dt = self._parse_datetime_safe(timestamp) if timestamp else None
                if dt:
                    login_hours.append(dt.hour)

            if not login_hours:
                continue

            # Détection simple: connexions entre 22h et 6h
            night_logins = [h for h in login_hours if h >= 22 or h <= 6]
            if night_logins:
                anomalies.append(
                    {
                        "user": user,
                        "anomaly_type": "unusual_hours",
                        "night_logins": len(night_logins),
                        "total_logins": len(login_hours),
                        "unusual_hours": night_logins,
                    }
                )

        return anomalies

    def _network_bucket(self, ip_str: str) -> Optional[str]:
        """
        Regroupe les IPs par réseau (/24 pour IPv4, /64 pour IPv6) pour limiter les faux positifs.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            else:
                net = ipaddress.ip_network(f"{ip_str}/64", strict=False)
            return str(net)
        except ValueError:
            return None

    def _detect_multiple_locations(
        self, successful_logins: Dict[str, List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """
        Détecte les connexions depuis plusieurs localisations géographiques
        - Par défaut, on agrège par réseau (/24 IPv4, /64 IPv6) pour réduire le bruit DHCP/VPN.
        - Si la géolocalisation (pays) est fournie dans les entrées (clé 'geolocation' avec 'country'),
          on s'appuie d'abord sur les pays, puis on retombe sur les réseaux sinon.
        """
        anomalies: List[Dict[str, Any]] = []

        for user, logins in successful_logins.items():
            if not logins:
                continue

            # 1) Si on a des pays, on agrège par pays
            countries: Set[str] = set()
            for login in logins:
                geo = login.get("geolocation") or {}
                country = geo.get("country")
                if country:
                    countries.add(country)

            if countries and len(countries) > 1:
                anomalies.append(
                    {
                        "user": user,
                        "anomaly_type": "multiple_locations",
                        "by": "country",
                        "unique_locations": sorted(list(countries)),
                        "location_count": len(countries),
                        "total_logins": len(logins),
                    }
                )
                # Si plusieurs pays => suffisant pour signaler
                continue

            # 2) Sinon, fallback: regrouper par réseau
            networks: Set[str] = set()
            ips: Set[str] = set()
            for login in logins:
                ip = login.get("ip")
                if not ip:
                    continue
                ips.add(ip)
                bucket = self._network_bucket(ip)
                if bucket:
                    networks.add(bucket)

            # Seulement si le volume d'IPs est raisonnable
            if len(ips) >= self.multi_location_ip_threshold and len(networks) >= self.multi_location_networks_threshold:
                anomalies.append(
                    {
                        "user": user,
                        "anomaly_type": "multiple_locations",
                        "by": "network",
                        "unique_networks": sorted(list(networks))[:10],
                        "network_count": len(networks),
                        "unique_ips": sorted(list(ips))[:10],
                        "ip_count": len(ips),
                        "total_logins": len(logins),
                    }
                )

        return anomalies

    def _detect_account_takeover(
        self,
        successful_logins: Dict[str, List[Dict[str, Any]]],
        failed_attempts: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """
        Détecte les indicateurs de compromission de compte
        """
        indicators: List[Dict[str, Any]] = []

        for user in successful_logins:
            if user not in failed_attempts:
                continue

            failed_count = len(failed_attempts[user])
            success_count = len(successful_logins[user])

            # Pattern simple: beaucoup d'échecs suivis de succès
            if failed_count > 10 and success_count > 0:
                indicators.append(
                    {
                        "user": user,
                        "anomaly_type": "potential_account_takeover",
                        "failed_attempts": failed_count,
                        "successful_logins": success_count,
                        "risk_score": min(failed_count * 2, 100),
                    }
                )

        return indicators

    # ---------------------------
    # Analyse des payloads
    # ---------------------------
    def analyze_payload_threats(self, log_entries: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Analyse les payloads des logs pour détecter les menaces

        Args:
            log_entries: Entrées de logs parsées

        Returns:
            Menaces détectées par type
        """
        threats: Dict[str, List[Dict[str, Any]]] = {t: [] for t in self.compiled_patterns}

        for entry in log_entries:
            raw_line = entry.get("raw_line", "") or ""
            for threat_type, patterns in self.compiled_patterns.items():
                for pattern in patterns:
                    if pattern.search(raw_line):
                        threats[threat_type].append(
                            {
                                "line": raw_line,
                                "ip": entry.get("ip"),
                                "user": entry.get("user"),
                                "timestamp": entry.get("timestamp"),
                                "pattern_matched": pattern.pattern,
                            }
                        )
                        break  # Une seule détection par ligne et par type

        return threats

    # ---------------------------
    # Utilitaires IP
    # ---------------------------
    def _is_private_ip(self, ip: str) -> bool:
        """Détermine si une IP est privée (IPv4/IPv6)"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    # ---------------------------
    # Résumé de sécurité
    # ---------------------------
    def generate_security_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Génère un résumé de sécurité

        Args:
            analysis_results: Résultats d'analyse

        Returns:
            Résumé de sécurité
        """
        bruteforce_attacks: Dict[str, Dict[str, Any]] = analysis_results.get("bruteforce_attacks", {}) or {}
        anomalies: Dict[str, List[Dict[str, Any]]] = analysis_results.get("anomalies", {}) or {}
        payload_threats: Dict[str, List[Dict[str, Any]]] = analysis_results.get("payload_threats", {}) or {}

        # Scores / IPs à haut risque
        total_threat_score = 0.0
        high_risk_ips: List[str] = []
        for ip, attack_data in bruteforce_attacks.items():
            threat_score = float(attack_data.get("threat_score", 0.0) or 0.0)
            total_threat_score += threat_score
            if threat_score > 70:
                high_risk_ips.append(ip)

        total_anomalies = sum(len(v) for v in anomalies.values())
        total_payload_threats = sum(len(v) for v in payload_threats.values())
        avg_threat_score = total_threat_score / max(len(bruteforce_attacks), 1)

        # Niveau de risque global (heuristique simple)
        if len(high_risk_ips) > 5 or total_anomalies > 10:
            risk_level = "CRITIQUE"
        elif len(high_risk_ips) > 2 or total_anomalies > 5:
            risk_level = "ÉLEVÉ"
        elif len(bruteforce_attacks) > 0 or total_anomalies > 0:
            risk_level = "MOYEN"
        else:
            risk_level = "FAIBLE"

        return {
            "risk_level": risk_level,
            "total_attacks": len(bruteforce_attacks),
            "high_risk_ips": high_risk_ips,
            "total_anomalies": total_anomalies,
            "payload_threats": total_payload_threats,
            "avg_threat_score": avg_threat_score,
            "recommendations": self._generate_recommendations(analysis_results, risk_level),
        }

    def _generate_recommendations(
        self, analysis_results: Dict[str, Any], risk_level: str
    ) -> List[str]:
        """
        Génère des recommandations de sécurité basées sur l'analyse
        """
        recommendations: List[str] = []

        bruteforce_attacks: Dict[str, Dict[str, Any]] = analysis_results.get("bruteforce_attacks", {}) or {}
        anomalies: Dict[str, List[Dict[str, Any]]] = analysis_results.get("anomalies", {}) or {}

        # Recommandations basées sur les attaques par force brute
        if bruteforce_attacks:
            high_threat_ips = [
                ip for ip, data in bruteforce_attacks.items() if float(data.get("threat_score", 0.0) or 0.0) > 70
            ]

            if high_threat_ips:
                recommendations.extend(
                    [
                        f"URGENT: Bloquer immédiatement les IPs suivantes: {', '.join(high_threat_ips[:5])}",
                        "Mettre en place un système de blocage automatique après 3 tentatives échouées.",
                        "Configurer des délais exponentiels entre les tentatives de connexion.",
                    ]
                )

            # Utilisateurs les plus ciblés
            targeted_users: Dict[str, int] = {}
            for attack_data in bruteforce_attacks.values():
                for user in attack_data.get("targeted_users", []):
                    targeted_users[user] = targeted_users.get(user, 0) + 1

            most_targeted = sorted(targeted_users.items(), key=lambda x: x[1], reverse=True)[:3]
            if most_targeted:
                users_list = ", ".join([f"{user} ({count} attaques)" for user, count in most_targeted])
                recommendations.append(
                    f"Renforcer la sécurité des comptes les plus ciblés: {users_list}."
                )

        # Recommandations basées sur les anomalies
        if anomalies.get("unusual_login_times"):
            recommendations.append("Surveiller et alerter les connexions en dehors des heures de bureau.")

        if anomalies.get("multiple_locations"):
            recommendations.append("Activer des alertes pour les connexions depuis plusieurs pays ou réseaux.")

        account_takeover = anomalies.get("account_takeover_indicators", [])
        if account_takeover:
            compromised_users = [indicator.get("user", "?") for indicator in account_takeover]
            if compromised_users:
                recommendations.append(
                    f"Vérifier l'intégrité des comptes suivants (reset mot de passe, MFA, audit): "
                    f"{', '.join(compromised_users[:3])}."
                )

        # Recommandations générales basées sur le niveau de risque
        if risk_level == "CRITIQUE":
            recommendations.extend(
                [
                    "CRITIQUE: Activer immédiatement les mécanismes de défense (MFA, blocage IP, verrouillage comptes).",
                    "Alerter l'équipe de sécurité et déclencher les procédures d'incident.",
                    "Effectuer un audit complet des hôtes et services exposés.",
                ]
            )
        elif risk_level == "ÉLEVÉ":
            recommendations.extend(
                [
                    "Activer l'authentification multi-facteurs pour tous les comptes privilégiés.",
                    "Augmenter la fréquence de surveillance et la rétention des logs.",
                ]
            )

        # Recommandations générales
        recommendations.extend(
            [
                "Mettre à jour les règles du pare-feu pour bloquer les IPs malveillantes.",
                "Configurer des alertes automatiques pour les tentatives de connexion suspectes.",
                "Effectuer des audits réguliers des comptes et droits utilisateurs.",
                "Sensibiliser les utilisateurs aux bonnes pratiques de sécurité.",
            ]
        )

        # Dédupliquer tout en conservant l'ordre
        deduped: List[str] = []
        seen: Set[str] = set()
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                deduped.append(rec)

        return deduped[:10]  # Limiter à 10 recommandations
