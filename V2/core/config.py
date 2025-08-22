"""
Gestionnaire de configuration pour l'analyseur de logs
"""

import json
import os
import logging
from typing import Dict, Any


class ConfigManager:
    """Gestionnaire de configuration centralisé"""

    DEFAULT_CONFIG = {
        "log_dir": "logs",
        "report_file": "rapport.html",
        "bruteforce_threshold": 5,
        "time_window_minutes": 60,
        "enable_geolocation": True,
        "geolocation_service": "ip-api.com",
        "max_geolocation_requests": 100,
        "suspicious_users": [
            "admin", "administrator", "root", "test", "guest",
            "oracle", "postgres", "mysql", "www-data", "apache",
            "nginx", "ftp", "mail", "backup", "service"
        ],
        "log_level": "INFO",
        "output_formats": ["html"],
        "analysis_options": {
            "detect_bruteforce": True,
            "analyze_temporal_patterns": True,
            "track_user_agents": False,
            "analyze_geographic_patterns": True
        },
        "alert_thresholds": {
            "critical_attempts_per_hour": 50,
            "suspicious_countries": [],
            "max_failed_attempts_per_ip": 10
        },
        "report_styling": {
            "theme": "modern",
            "include_charts": True,
            "show_geolocation": True,
            "include_recommendations": True  # ✅ ajouté
        }
    }

    def __init__(self, config_file: str = "config.json"):
        """
        Initialise le gestionnaire de configuration

        Args:
            config_file: Chemin vers le fichier de configuration
        """
        self.config_file = config_file
        self.logger = logging.getLogger(__name__)  # ✅ logger avant load_config
        logging.basicConfig(
            level=getattr(logging, self.DEFAULT_CONFIG["log_level"]),
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """
        Charge la configuration depuis le fichier ou crée un fichier par défaut

        Returns:
            Dictionnaire de configuration
        """
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)

                # Merger avec la configuration par défaut pour les nouvelles clés
                config = self.DEFAULT_CONFIG.copy()
                self._deep_update(config, loaded_config)

                # Valider la configuration
                self._validate_config(config)

                return config
            else:
                # Créer le fichier de configuration par défaut
                self.save_config(self.DEFAULT_CONFIG)
                print(f" Fichier de configuration créé: {self.config_file}")
                return self.DEFAULT_CONFIG.copy()

        except json.JSONDecodeError as e:
            self.logger.error(f"Erreur de syntaxe JSON dans {self.config_file}: {e}")
            print(f" Erreur dans le fichier de configuration. Utilisation des valeurs par défaut.")
            return self.DEFAULT_CONFIG.copy()
        except Exception as e:
            self.logger.warning(f"Erreur lors du chargement de la configuration: {e}")
            return self.DEFAULT_CONFIG.copy()

    def save_config(self, config: Dict[str, Any] = None) -> bool:
        """
        Sauvegarde la configuration dans le fichier

        Args:
            config: Configuration à sauvegarder (utilise self.config si None)

        Returns:
            True si succès, False sinon
        """
        try:
            config_to_save = config if config is not None else self.config

            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_to_save, f, indent=4, ensure_ascii=False)

            self.logger.info(f"Configuration sauvegardée: {self.config_file}")
            return True

        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde de la configuration: {e}")
            return False

    def _deep_update(self, base_dict: Dict, update_dict: Dict):
        """
        Met à jour récursivement un dictionnaire
        """
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def _validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Valide les valeurs de configuration
        """
        # Validation des types et valeurs critiques
        if not isinstance(config.get('bruteforce_threshold'), int) or config['bruteforce_threshold'] < 1:
            raise ValueError("bruteforce_threshold doit être un entier positif")

        if not isinstance(config.get('time_window_minutes'), int) or config['time_window_minutes'] < 1:
            raise ValueError("time_window_minutes doit être un entier positif")

        # Validation des chemins
        log_dir = config.get('log_dir', '')
        if not log_dir or not isinstance(log_dir, str):
            raise ValueError("log_dir doit être une chaîne non vide")
        if not os.path.exists(log_dir):  # ✅ création auto du dossier
            os.makedirs(log_dir, exist_ok=True)

        # Validation des formats de sortie
        valid_formats = ['html', 'json', 'txt']
        output_formats = config.get('output_formats', [])
        if not isinstance(output_formats, list) or not output_formats:
            config['output_formats'] = ['html']
        else:
            for fmt in output_formats:
                if fmt not in valid_formats:
                    self.logger.warning(f"Format de sortie non supporté: {fmt}")

        return True

    def get(self, key: str, default=None):
        """Récupère une valeur de configuration (notation pointée supportée)"""
        keys = key.split('.')
        value = self.config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> bool:
        """
        Définit une valeur de configuration (fusionne si dict)
        """
        try:
            keys = key.split('.')
            config = self.config

            for k in keys[:-1]:
                if k not in config or not isinstance(config[k], dict):
                    config[k] = {}
                config = config[k]

            # ✅ fusion intelligente si c’est un dict
            if isinstance(config.get(keys[-1]), dict) and isinstance(value, dict):
                self._deep_update(config[keys[-1]], value)
            else:
                config[keys[-1]] = value

            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la définition de {key}: {e}")
            return False

    def get_analysis_config(self) -> Dict[str, Any]:
        """Retourne la configuration spécifique à l'analyse"""
        return {
            'bruteforce_threshold': self.get('bruteforce_threshold'),
            'time_window_minutes': self.get('time_window_minutes'),
            'suspicious_users': self.get('suspicious_users', []),
            'enable_geolocation': self.get('enable_geolocation'),
            'analysis_options': self.get('analysis_options', {}),
            'alert_thresholds': self.get('alert_thresholds', {})
        }

    def get_report_config(self) -> Dict[str, Any]:
        """Retourne la configuration spécifique aux rapports"""
        return {
            'report_file': self.get('report_file'),
            'output_formats': self.get('output_formats', ['html']),
            'report_styling': self.get('report_styling', {}),
            'include_recommendations': self.get('report_styling.include_recommendations', True)
        }

    def update_from_args(self, args) -> None:
        """Met à jour la configuration avec les arguments de ligne de commande"""
        if hasattr(args, 'log_dir') and args.log_dir:
            self.set('log_dir', args.log_dir)

        if hasattr(args, 'output') and args.output:
            self.set('report_file', args.output)

        if hasattr(args, 'threshold') and args.threshold:
            self.set('bruteforce_threshold', args.threshold)

        if hasattr(args, 'verbose') and args.verbose:
            self.set('log_level', 'DEBUG')

        if hasattr(args, 'no_geo') and args.no_geo:
            self.set('enable_geolocation', False)

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        self.set(key, value)
