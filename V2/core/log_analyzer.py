"""
Analyseur principal de logs de sécurité
Intègre tous les composants pour une analyse complète
"""

import logging
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, Any
from datetime import datetime

# ⚠️ Attention : utiliser des imports absolus si exécuté directement
from config import ConfigManager
from patterns import PatternManager
from geolocation import GeolocationService
from security import SecurityAnalyzer
from report import ReportGenerator


class LogAnalyzer:
    """
    Analyseur principal de logs de sécurité
    Coordonne tous les composants pour une analyse complète
    """
    
    def __init__(self, config_file: str = "config.json"):
        """Initialise l'analyseur avec la configuration"""
        self.config_manager = ConfigManager(config_file)
        self.config = self.config_manager.config

        self._last_results: Dict[str, Any] | None = None

        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Initialiser les modules spécialisés
        self.pattern_manager = PatternManager()
        self.geo_service = GeolocationService(self.config)
        self.security_analyzer = SecurityAnalyzer(self.config)
        self.report_generator = ReportGenerator(self.config)
        
        self.logger.info("Analyseur de logs initialisé avec succès")
    
    def setup_logging(self):
        """Configure le système de logging"""
        log_level = getattr(logging, self.config.get('log_level', 'INFO'), logging.INFO)
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('analyzer.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyse un fichier de log spécifique"""
        self.logger.info(f"Analyse du fichier: {file_path}")
        
        results = {
            'file_path': file_path,
            'failed_attempts': defaultdict(list),
            'successful_logins': defaultdict(list),
            'raw_events': [],
            'parsing_stats': {
                'total_lines': 0,
                'parsed_lines': 0,
                'error_lines': 0
            }
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    results['parsing_stats']['total_lines'] += 1
                    if not line.strip():
                        continue
                    
                    parsed_event = self.pattern_manager.parse_line(line)
                    if parsed_event:
                        results['parsing_stats']['parsed_lines'] += 1
                        results['raw_events'].append(parsed_event)
                        self._classify_event(parsed_event, results)
                    else:
                        results['parsing_stats']['error_lines'] += 1
                        if self.logger.isEnabledFor(logging.DEBUG):
                            self.logger.debug(
                                f"Ligne non reconnue {file_path}:{line_num}: {line[:100]}"
                            )
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse de {file_path}: {e}")
            results['error'] = str(e)
        
        return results
    
    def _classify_event(self, event: Dict, results: Dict):
        """Classe un événement parsé dans les bonnes catégories"""
        event_type = event.get('event_type')
        user = event.get('user')
        ip = event.get('ip')
        timestamp = event.get('timestamp')
        
        if not ip or not event_type:
            return
        
        event_data = {
            'ip': ip,
            'timestamp': timestamp,
            'pattern_name': event.get('pattern_name'),
            'raw_line': event.get('raw_line', ''),
            'normalized_timestamp': event.get('normalized_timestamp')
        }
        
        if event_type == 'failed':
            results['failed_attempts'][user or '_unknown_user'].append(event_data)
        elif event_type == 'success':
            results['successful_logins'][user or '_unknown_user'].append(event_data)
    
    def run_analysis(self) -> Dict[str, Any]:
        """Lance l'analyse complète des logs"""
        self.logger.info("Démarrage de l'analyse complète")
        
        log_dir = Path(self.config['log_dir'])
        if not log_dir.exists():
            raise FileNotFoundError(f"Le dossier de logs {log_dir} n'existe pas")
        
        global_results = {
            'file_analysis': {},
            'total_failed': 0,
            'total_success': 0,
            'all_failed_attempts': defaultdict(list),
            'all_successful_logins': defaultdict(list),
            'all_raw_events': [],
            'suspicious_ips': set()
        }
        
        log_files = [f for f in log_dir.iterdir() if f.is_file()]
        self.logger.info(f"Fichiers trouvés: {len(log_files)}")
        
        for log_file in log_files:
            file_results = self.analyze_file(str(log_file))
            global_results['file_analysis'][log_file.name] = file_results
            
            for user, attempts in file_results['failed_attempts'].items():
                global_results['all_failed_attempts'][user].extend(attempts)
                global_results['total_failed'] += len(attempts)
            for user, logins in file_results['successful_logins'].items():
                global_results['all_successful_logins'][user].extend(logins)
                global_results['total_success'] += len(logins)
            global_results['all_raw_events'].extend(file_results['raw_events'])
        
        self.logger.info("Analyse de sécurité en cours...")
        global_results.update(self._run_security_analysis(global_results))
        
        if self.config.get('enable_geolocation', True):
            self.logger.info("Géolocalisation des IPs en cours...")
            self._add_geolocation_data(global_results)
        
        self.logger.info("Génération des rapports...")
        self._generate_reports(global_results)
        
        self._last_results = global_results
        self.logger.info("Analyse terminée avec succès")
        return global_results
    
    def _run_security_analysis(self, results: Dict) -> Dict:
        """Lance l'analyse de sécurité avancée"""
        security_results = {}
        
        if self.config.get('analysis_options', {}).get('detect_bruteforce', True):
            bruteforce_attacks = self.security_analyzer.detect_bruteforce_attacks(
                results['all_failed_attempts']
            )
            security_results['bruteforce_attacks'] = bruteforce_attacks
            results['suspicious_ips'].update(bruteforce_attacks.keys())
        
        if self.config.get('analysis_options', {}).get('analyze_temporal_patterns', True):
            anomalies = self.security_analyzer.detect_anomalies(
                results['all_successful_logins'],
                results['all_failed_attempts']
            )
            security_results['anomalies'] = anomalies
        
        payload_threats = self.security_analyzer.analyze_payload_threats(
            results['all_raw_events']
        )
        security_results['payload_threats'] = payload_threats
        
        timestamps = [e['timestamp'] for e in results['all_raw_events'] if e.get('timestamp')]
        temporal_patterns = self.security_analyzer._analyze_temporal_pattern(timestamps)
        security_results['temporal_patterns'] = temporal_patterns
        
        return security_results
    
    def _add_geolocation_data(self, results: Dict):
        """Ajoute les données de géolocalisation aux résultats"""
        all_ips = set()
        all_ips.update(results.get('bruteforce_attacks', {}).keys())
        
        for attempts in results.get('all_failed_attempts', {}).values():
            all_ips.update(a.get('ip') for a in attempts if a.get('ip'))
        for logins in results.get('all_successful_logins', {}).values():
            all_ips.update(l.get('ip') for l in logins if l.get('ip'))
        
        self.logger.info(f"Géolocalisation de {len(all_ips)} IPs uniques...")
        ip_locations = self.geo_service.bulk_geolocate(all_ips)
        
        for ip, attack_data in results.get('bruteforce_attacks', {}).items():
            if ip in ip_locations:
                attack_data['geolocation'] = ip_locations[ip]
        
        results['ip_geolocations'] = ip_locations
        results['geolocation_stats'] = self.geo_service.get_stats()
        self.logger.info(
            f"Géolocalisation terminée: {results['geolocation_stats']['requests_made']} requêtes utilisées"
        )
    
    def _generate_reports(self, results: Dict):
        """Génère les rapports dans les formats demandés"""
        security_summary = self.security_analyzer.generate_security_summary(results)
        results['security_summary'] = security_summary
        
        report_file = self.config.get('report_file', 'rapport.html')
        
        for fmt in self.config.get('output_formats', ['html']):
            if fmt == 'html':
                self.report_generator.generate_html_report(results, security_summary)
            elif fmt == 'json':
                self._generate_json_report(results, report_file)
            elif fmt == 'txt':
                self._generate_text_report(results, security_summary, report_file)
    
    def _generate_json_report(self, results: Dict, report_file: str):
        """Génère un rapport au format JSON"""
        json_file = report_file.replace('.html', '.json')
        try:
            json_data = {
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_failed_attempts': results.get('total_failed', 0),
                    'total_successful_logins': results.get('total_success', 0),
                    'suspicious_ips_count': len(results.get('suspicious_ips', set())),
                    'bruteforce_attacks_count': len(results.get('bruteforce_attacks', {})),
                    'risk_level': results.get('security_summary', {}).get('risk_level', 'UNKNOWN')
                },
                'bruteforce_attacks': results.get('bruteforce_attacks', {}),
                'anomalies': results.get('anomalies', {}),
                'geolocation_stats': results.get('geolocation_stats', {}),
                'file_analysis': {}
            }
            for filename, data in results.get('file_analysis', {}).items():
                json_data['file_analysis'][filename] = {
                    'total_lines': data.get('parsing_stats', {}).get('total_lines', 0),
                    'parsed_lines': data.get('parsing_stats', {}).get('parsed_lines', 0),
                    'failed_attempts_count': sum(len(a) for a in data.get('failed_attempts', {}).values()),
                    'successful_logins_count': sum(len(l) for l in data.get('successful_logins', {}).values())
                }
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)
            self.logger.info(f"Rapport JSON généré: {json_file}")
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du rapport JSON: {e}")
    
    def _generate_text_report(self, results: Dict, security_summary: Dict, report_file: str):
        """Génère un rapport au format texte"""
        txt_file = report_file.replace('.html', '.txt')
        try:
            with open(txt_file, 'w', encoding='utf-8', errors="ignore") as f:
                f.write("="*60 + "\n")
                f.write("           RAPPORT D'ANALYSE DE SECURITE\n")
                f.write("="*60 + "\n")
                f.write(f"Généré le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("RESUME EXECUTIF\n" + "-"*20 + "\n")
                f.write(f"Niveau de risque: {security_summary.get('risk_level', 'INCONNU')}\n")
                f.write(f"Attaques détectées: {security_summary.get('total_attacks', 0)}\n")
                f.write(f"IPs à haut risque: {len(security_summary.get('high_risk_ips', []))}\n")
                f.write(f"Anomalies détectées: {security_summary.get('total_anomalies', 0)}\n\n")
                
                f.write("STATISTIQUES GLOBALES\n" + "-"*25 + "\n")
                f.write(f"Tentatives échouées: {results.get('total_failed', 0)}\n")
                f.write(f"Connexions réussies: {results.get('total_success', 0)}\n")
                f.write(f"IPs suspectes: {len(results.get('suspicious_ips', set()))}\n")
                f.write(f"Fichiers analysés: {len(results.get('file_analysis', {}))}\n\n")
                
                bruteforce_attacks = results.get('bruteforce_attacks', {})
                if bruteforce_attacks:
                    f.write("TOP 10 DES ATTAQUES LES PLUS DANGEREUSES\n" + "-"*42 + "\n")
                    sorted_attacks = sorted(
                        bruteforce_attacks.items(),
                        key=lambda x: x[1].get('threat_score', 0),
                        reverse=True
                    )
                    for i, (ip, data) in enumerate(sorted_attacks[:10], 1):
                        score = data.get('threat_score', 0)
                        attempts = data.get('total_attempts', 0)
                        attack_type = data.get('attack_type', 'unknown')
                        country = data.get('geolocation', {}).get('country', 'Inconnu')
                        f.write(f"{i:2d}. {ip} ({country})\n")
                        f.write(f"    Score: {score:.1f}/100 | Tentatives: {attempts} | Type: {attack_type}\n")
                    f.write("\n")
                
                recs = security_summary.get('recommendations', [])
                if recs:
                    f.write("RECOMMANDATIONS PRIORITAIRES\n" + "-"*30 + "\n")
                    for i, rec in enumerate(recs, 1):
                        clean_rec = rec.encode('ascii', 'ignore').decode('ascii')
                        f.write(f"{i:2d}. {clean_rec}\n")
            
            self.logger.info(f"Rapport TXT généré: {txt_file}")
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du rapport TXT: {e}")
    
    def get_analysis_summary(self) -> Dict:
        """Retourne un résumé rapide de la dernière analyse"""
        if not self._last_results:
            return {'error': 'Aucune analyse effectuée'}
        
        results = self._last_results
        return {
            'files_analyzed': len(results.get('file_analysis', {})),
            'total_failed_attempts': results.get('total_failed', 0),
            'total_successful_logins': results.get('total_success', 0),
            'suspicious_ips': len(results.get('suspicious_ips', set())),
            'bruteforce_attacks': len(results.get('bruteforce_attacks', {})),
            'risk_level': results.get('security_summary', {}).get('risk_level', 'UNKNOWN'),
            'top_threat_ip': self._get_top_threat_ip(results)
        }
    
    def _get_top_threat_ip(self, results: Dict) -> Dict:
        """Retourne l'IP la plus menaçante"""
        bruteforce_attacks = results.get('bruteforce_attacks', {})
        if not bruteforce_attacks:
            return {}
        top_ip, top_data = max(
            bruteforce_attacks.items(),
            key=lambda x: x[1].get('threat_score', 0)
        )
        return {
            'ip': top_ip,
            'threat_score': top_data.get('threat_score', 0),
            'total_attempts': top_data.get('total_attempts', 0),
            'attack_type': top_data.get('attack_type', 'unknown'),
            'country': top_data.get('geolocation', {}).get('country', 'Inconnu')
        }
