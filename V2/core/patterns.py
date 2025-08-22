"""
- Définit les expressions régulières pour détecter des événements
dans les logs (authentifications échouées, scans, etc.)
"""

import re
import logging
import ipaddress
from datetime import datetime
from typing import Optional, Dict, Any, List


class LogPattern:
    """
    Représente un pattern de log avec regex + groupes (timestamp, user, ip).
    """
    def __init__(self, name: str, pattern: str, description: str,
                 timestamp_group: Optional[int] = None,
                 user_group: Optional[int] = None,
                 ip_group: Optional[int] = None):
        self.name = name
        self.pattern = re.compile(pattern)
        self.description = description
        self.timestamp_group = timestamp_group
        self.user_group = user_group
        self.ip_group = ip_group
        self.logger = logging.getLogger(__name__)

    def match(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Vérifie si une ligne correspond au pattern.
        Retourne dict avec infos extraites si succès.
        """
        match = self.pattern.search(line)
        if not match:
            return None

        groups = match.groups()
        result: Dict[str, Any] = {
            'pattern': self.name,
            'description': self.description
        }

        try:
            if self.timestamp_group and self.timestamp_group <= len(groups):
                result['timestamp'] = groups[self.timestamp_group - 1]
            if self.user_group and self.user_group <= len(groups):
                result['user'] = groups[self.user_group - 1]
            if self.ip_group and self.ip_group <= len(groups):
                ip = groups[self.ip_group - 1]
                if self._is_valid_ip(ip):
                    result['ip'] = ip
        except IndexError:
            pass

        return result

    def _is_valid_ip(self, ip: str) -> bool:
        """Vérifie si l'IP est valide (IPv4 ou IPv6)."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si l'IP est privée."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _normalize_timestamp(self, timestamp: str) -> Optional[datetime]:
        """
        Normalise le timestamp en objet datetime.
        Essaie plusieurs formats connus.
        """
        formats = [
            '%b %d %H:%M:%S',        # "Jan 12 15:04:05"
            '%Y-%m-%d %H:%M:%S',     # "2025-08-22 14:55:00"
            '%d/%b/%Y:%H:%M:%S',     # "22/Aug/2025:14:55:00"
        ]

        for fmt in formats:
            try:
                if fmt == '%b %d %H:%M:%S':
                    # Ajout automatique de l'année courante
                    year = datetime.now().year
                    ts_with_year = f"{year} {timestamp}"
                    return datetime.strptime(ts_with_year, f'%Y {fmt}')
                return datetime.strptime(timestamp, fmt)
            except ValueError:
                continue

        self.logger.debug(f"Impossible de parser le timestamp: {timestamp}")
        return None


class PatternManager:
    """Gestionnaire de plusieurs patterns de logs."""
    def __init__(self):
        self.patterns: List[LogPattern] = []
        self._load_patterns()
    def test_patterns(self, log_lines: list) -> dict:
        """Teste plusieurs lignes et retourne un résumé des matches/non-matches."""
        matched = []
        unmatched = []
        pattern_usage = {p.name: 0 for p in self.patterns}

        for line in log_lines:
            line_matched = False
            for pattern in self.patterns:
                if pattern.match(line):
                    matched.append(line)
                    pattern_usage[pattern.name] += 1
                    line_matched = True
                    break
            if not line_matched:
                unmatched.append(line)

        return {
            'matched': matched,
            'unmatched': unmatched,
            'pattern_usage': pattern_usage
        }

    def _load_patterns(self):
        """Charge les patterns prédéfinis et supplémentaires pour tests."""
        self.patterns = [
            # SSH
            LogPattern(
                name="ssh_failed_login",
                pattern=r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Failed password for ([^\s]+) from ([\da-fA-F:.]+)',
                description="SSH authentication failed",
                timestamp_group=1, user_group=2, ip_group=3
            ),
            LogPattern(
                name="ssh_successful_login",
                pattern=r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Accepted password for ([^\s]+) from ([\da-fA-F:.]+)',
                description="SSH authentication success",
                timestamp_group=1, user_group=2, ip_group=3
            ),
            LogPattern(
                name="ssh_invalid_user",
                pattern=r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Invalid user ([^\s]+) from ([\da-fA-F:.]+)',
                description="SSH invalid user attempt",
                timestamp_group=1, user_group=2, ip_group=3
            ),
            LogPattern(
                name="ssh_failed_login_modern",
                pattern=r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) Failed login attempt for user ([^\s]+) from ([\da-fA-F:.]+)',
                description="SSH failed login attempt (modern format)",
                timestamp_group=1, user_group=2, ip_group=3
            ),

            # Apache
            LogPattern(
                name="apache_404",
                pattern=r'\[(.*?)\] \[error\] \[client ([\da-fA-F:.]+)\] File does not exist: (.*)',
                description="Apache 404 error",
                timestamp_group=1, ip_group=2
            ),
            LogPattern(
                name="apache_auth_failed",
                pattern=r'\[(.*?)\] \[error\] \[client ([\da-fA-F:.]+)\] user ([^\s]+) not found',
                description="Apache authentication failed",
                timestamp_group=1, ip_group=2, user_group=3
            ),
            LogPattern(
                name="apache_401",
                pattern=r'([\d./:A-Za-z]+) - - \[([^\]]+)\] "GET (.*?) HTTP/1\.[01]" 401',
                description="Apache 401 unauthorized",
                timestamp_group=2, ip_group=1
            ),

            # Nginx
            LogPattern(
                name="nginx_404",
                pattern=r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[error\] \d+#\d+: \*.*? "GET (.*?) HTTP/1\.[01]" 404',
                description="Nginx 404 error",
                timestamp_group=1
            ),

            # FTP
            LogPattern(
                name="ftp_fail_login",
                pattern=r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*FAIL LOGIN: user="([^\"]+)" rhost=([\da-fA-F:.]+)',
                description="FTP failed login",
                timestamp_group=1, user_group=2, ip_group=3
            ),
        ]

    def match_line(self, line: str) -> List[Dict[str, Any]]:
        """Teste une ligne contre tous les patterns connus."""
        matches: List[Dict[str, Any]] = []
        for pattern in self.patterns:
            result = pattern.match(line)
            if result:
                matches.append(result)
        return matches
