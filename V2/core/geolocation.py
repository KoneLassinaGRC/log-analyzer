"""
Service de géolocalisation des adresses IP
"""

from typing import Dict, Optional, Set, Callable
import requests
import time
import logging
import ipaddress
import json
import os
from requests.adapters import HTTPAdapter, Retry


class GeolocationService:
    """Service de géolocalisation avec cache et limitation de requêtes"""

    DEFAULT_CACHE_FILE = "geolocation_cache.json"
    DEFAULT_MAX_REQUESTS = 100

    def __init__(self, config: Dict):
        """
        Args:
            config: dictionnaire de configuration (peut contenir les clés suivantes)
                - enable_geolocation: bool
                - max_geolocation_requests: int
                - geolocation_service: str (clé parmi self.services)
                - geolocation_cache_file: str (chemin vers le fichier cache)
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.request_count = 0
        self.max_requests = int(self.config.get("max_geolocation_requests", self.DEFAULT_MAX_REQUESTS))
        self.cache_file = self.config.get("geolocation_cache_file", self.DEFAULT_CACHE_FILE)
        self.cache: Dict[str, Dict] = self._load_cache()

        # Préparer une session requests avec retry/backoff raisonnable
        self.session = requests.Session()
        retries = Retry(total=2, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))
        self.session.mount("http://", HTTPAdapter(max_retries=retries))
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

        # Services disponibles (clé -> méthode)
        self.services: Dict[str, Callable[[str], Dict[str, object]]] = {
            "ip-api.com": self._query_ip_api,
            "ipinfo.io": self._query_ipinfo,
            # placeholder pour extension future
            "geoip.com": self._query_geoip,
        }

        # Service courant
        self.current_service = self.config.get("geolocation_service", "ip-api.com")
        if self.current_service not in self.services:
            self.logger.warning("Service de géolocalisation '%s' non supporté, utilisation de ip-api.com", self.current_service)
            self.current_service = "ip-api.com"

    # ---------------------
    # Cache
    # ---------------------
    def _load_cache(self) -> Dict[str, Dict]:
        """Charge le cache à partir du fichier JSON (silencieusement si absent/incorrect)."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    if isinstance(data, dict):
                        return data
                    self.logger.debug("Format du cache invalide, réinitialisation.")
        except Exception as e:
            self.logger.debug("Impossible de charger le cache de géolocalisation: %s", e)
        return {}

    def _save_cache(self) -> None:
        """Sauvegarde le cache sur disque (tentative protégée)."""
        try:
            tmp = f"{self.cache_file}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.cache, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.cache_file)
        except Exception as e:
            self.logger.debug("Impossible de sauvegarder le cache de géolocalisation: %s", e)

    # ---------------------
    # Utilitaires IP
    # ---------------------
    def _is_valid_ip(self, ip: Optional[str]) -> bool:
        """Vérifie si la chaîne fournie est une adresse IP valide (IPv4 ou IPv6)."""
        if not ip or not isinstance(ip, str):
            return False
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_private_ip(self, ip: str) -> bool:
        """Retourne True si l'IP est privée (RFC1918 / loopback / unique-local IPv6)."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    # ---------------------
    # Méthodes publiques
    # ---------------------
    def get_location(self, ip: str) -> Dict[str, object]:
        """
        Obtient les informations de géolocalisation pour une IP.
        Résultat: dict avec clés (country, country_code, region, city, isp, org, timezone, lat, lon)
        """
        # Validation basique
        if not self.config.get("enable_geolocation", True):
            return self._empty_location()

        if not self._is_valid_ip(ip):
            self.logger.debug("IP invalide fournie à la géoloc: %s", ip)
            return self._empty_location()

        # IP privée -> information locale
        if self._is_private_ip(ip):
            return {
                "country": "Local Network",
                "country_code": "LAN",
                "region": "Private",
                "city": "Internal",
                "isp": "Local Network",
                "org": "Private Network",
                "timezone": "Local",
                "lat": 0.0,
                "lon": 0.0,
            }

        # Vérifier cache
        if ip in self.cache:
            return self.cache[ip]

        # Vérifier quota
        if self.request_count >= self.max_requests:
            self.logger.warning("Limite de requêtes de géolocalisation atteinte (%d)", self.max_requests)
            return self._empty_location()

        # Interroger le service choisi
        try:
            self.request_count += 1
            location = self._query_service(ip)
            # si donnée valide, mettre en cache
            if location and location.get("country") and location.get("country") != "Unknown":
                self.cache[ip] = location
                # Save opportuniste (évite pertes si plantage)
                self._save_cache()
            return location
        except Exception as e:
            self.logger.debug("Erreur get_location pour %s : %s", ip, e)
            return self._empty_location()

    def _query_service(self, ip: str) -> Dict[str, object]:
        """Appel au service configuré (wrapper)."""
        func = self.services.get(self.current_service)
        if not func:
            self.logger.error("Service de géolocalisation non configuré: %s", self.current_service)
            return self._empty_location()
        return func(ip)

    # ---------------------
    # Implémentations des services
    # ---------------------
    def _query_ip_api(self, ip: str) -> Dict[str, object]:
        """Interroge ip-api.com"""
        url = f"http://ip-api.com/json/{ip}"
        params = {"fields": "status,country,countryCode,region,regionName,city,isp,org,timezone,lat,lon"}
        try:
            resp = self.session.get(url, params=params, timeout=4)
            if resp.status_code != 200:
                self.logger.debug("ip-api: status %s for %s", resp.status_code, ip)
                return self._empty_location()
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "XX"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "timezone": data.get("timezone", "Unknown"),
                    "lat": float(data.get("lat", 0.0)) if data.get("lat") is not None else 0.0,
                    "lon": float(data.get("lon", 0.0)) if data.get("lon") is not None else 0.0,
                }
        except Exception as e:
            self.logger.debug("Erreur ip-api pour %s : %s", ip, e)
        return self._empty_location()

    def _query_ipinfo(self, ip: str) -> Dict[str, object]:
        """Interroge ipinfo.io (sans token). Pour usage intensif, prévoir token."""
        url = f"https://ipinfo.io/{ip}/json"
        try:
            resp = self.session.get(url, timeout=4)
            if resp.status_code != 200:
                self.logger.debug("ipinfo: status %s for %s", resp.status_code, ip)
                return self._empty_location()
            data = resp.json()
            loc = data.get("loc", "")
            lat, lon = 0.0, 0.0
            if loc:
                try:
                    parts = loc.split(",")
                    if len(parts) == 2:
                        lat = float(parts[0])
                        lon = float(parts[1])
                except Exception:
                    pass
            return {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("country", "XX"),
                "region": data.get("region", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("org", "Unknown"),
                "org": data.get("org", "Unknown"),
                "timezone": data.get("timezone", "Unknown"),
                "lat": lat,
                "lon": lon,
            }
        except Exception as e:
            self.logger.debug("Erreur ipinfo pour %s : %s", ip, e)
        return self._empty_location()

    def _query_geoip(self, ip: str) -> Dict[str, object]:
        """Stub pour un service additionnel (à implémenter si nécessaire)"""
        # Exemple: implémenter un autre fournisseur et renvoyer un dict équivalent
        return self._empty_location()

    # ---------------------
    # Bulk & maintenance
    # ---------------------
    def bulk_geolocate(self, ips: Set[str]) -> Dict[str, Dict]:
        """
        Géolocalise un ensemble d'IPs.
        - Utilise le cache quand disponible.
        - Interroge le service pour les IPs non-cachées jusqu'à la limite max_requests.
        - Retourne un dictionnaire ip -> location_dict.
        """
        results: Dict[str, Dict] = {}
        if not ips:
            return results

        # Vérifier configuration
        if not self.config.get("enable_geolocation", True):
            # Retourner uniquement des résultats vides ou locaux pour les privées
            for ip in ips:
                if self._is_valid_ip(ip) and self._is_private_ip(ip):
                    results[ip] = {
                        "country": "Local Network",
                        "country_code": "LAN",
                        "region": "Private",
                        "city": "Internal",
                        "isp": "Local Network",
                        "org": "Private Network",
                        "timezone": "Local",
                        "lat": 0.0,
                        "lon": 0.0,
                    }
                else:
                    results[ip] = self._empty_location()
            return results

        uncached = []
        for ip in ips:
            if not self._is_valid_ip(ip):
                results[ip] = self._empty_location()
                continue
            if ip in self.cache:
                results[ip] = self.cache[ip]
            elif self._is_private_ip(ip):
                results[ip] = {
                    "country": "Local Network",
                    "country_code": "LAN",
                    "region": "Private",
                    "city": "Internal",
                    "isp": "Local Network",
                    "org": "Private Network",
                    "timezone": "Local",
                    "lat": 0.0,
                    "lon": 0.0,
                }
            else:
                uncached.append(ip)

        # Interroger pour les IPs non-cachées
        for ip in uncached:
            if self.request_count >= self.max_requests:
                self.logger.warning("Limite de requêtes atteinte (%d). Les IPs restantes recevront des valeurs vides.", self.max_requests)
                results[ip] = self._empty_location()
                continue

            loc = self.get_location(ip)
            # get_location gère la mise en cache et l'incrémentation du compteur
            results[ip] = loc
            # léger délai pour éviter d'atteindre des limites strictes
            time.sleep(0.08)

        return results

    def cleanup_cache(self, max_size: int = 1000) -> None:
        """
        Nettoie le cache si trop volumineux en gardant les dernières entrées.
        max_size : taille maximale souhaitée du cache (nombre d'entrées).
        """
        try:
            if not isinstance(self.cache, dict):
                return
            size = len(self.cache)
            if size <= max_size:
                return
            # conserver les dernières `max_size` entrées (ordre insertion non garanti avant Python 3.7,
            # mais dict conserve l'ordre d'insertion en CPython 3.7+)
            items = list(self.cache.items())
            new_cache = dict(items[-max_size:])
            self.cache = new_cache
            self._save_cache()
            self.logger.info("Cache géolocalisation réduit: %d -> %d", size, len(self.cache))
        except Exception as e:
            self.logger.error("Erreur lors du nettoyage du cache: %s", e)

    # ---------------------
    # Statistiques & utilitaires
    # ---------------------
    def get_stats(self) -> Dict:
        """Retourne les statistiques du service"""
        return {
            "requests_made": self.request_count,
            "max_requests": self.max_requests,
            "cache_size": len(self.cache),
            "current_service": self.current_service,
            "remaining_requests": max(0, self.max_requests - self.request_count),
        }

    @staticmethod
    def _empty_location() -> Dict[str, object]:
        """Retourne une structure de localisation vide/placeholder"""
        return {
            "country": "Unknown",
            "country_code": "XX",
            "region": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "org": "Unknown",
            "timezone": "Unknown",
            "lat": 0.0,
            "lon": 0.0,
        }
