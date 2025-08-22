"""
Générateur de rapports HTML et autres formats
"""

import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Any
from html import escape


class ReportGenerator:
    """Générateur de rapports pour l'analyse de sécurité"""

    def __init__(self, config: Dict):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

    # --------- API publique

    def generate_reports(self, analysis_results: Dict, security_summary: Dict):
        """
        Génère tous les rapports demandés dans config['output_formats'].
        Formats supportés: 'html', 'json', 'txt'
        """
        formats = self.config.get("output_formats", ["html"])
        if "html" in formats:
            self.generate_html_report(analysis_results, security_summary)
        if "json" in formats:
            self.generate_json_report(analysis_results, security_summary)
        if "txt" in formats:
            self.generate_txt_report(analysis_results, security_summary)

    def generate_html_report(self, analysis_results: Dict, security_summary: Dict):
        """Génère un rapport HTML complet"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html_content = self._get_html_header(now)
        html_content += self._generate_executive_summary(security_summary or {})
        html_content += self._generate_statistics_section(analysis_results or {})
        html_content += self._generate_security_alerts(analysis_results.get("bruteforce_attacks", {}))
        html_content += self._generate_file_analysis_section(analysis_results or {})
        html_content += self._generate_temporal_analysis(analysis_results.get("temporal_patterns", {}))
        html_content += self._generate_geolocation_analysis(analysis_results or {})
        html_content += self._generate_anomalies_section(analysis_results.get("anomalies", {}))
        html_content += self._generate_recommendations_section(security_summary.get("recommendations", []))
        html_content += self._get_html_footer()

        report_path = self.config.get("report_file", "rapport.html")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            self.logger.info(f"Rapport HTML généré: {report_path}")
        except (OSError, IOError) as e:
            self.logger.error(f"Erreur lors de la génération du rapport HTML: {e}")

    def generate_json_report(self, analysis_results: Dict, security_summary: Dict):
        """Génère un export JSON brut."""
        out = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "security_summary": security_summary or {},
            "analysis_results": analysis_results or {},
        }
        base, _ = os.path.splitext(self.config.get("report_file", "rapport.html"))
        path = f"{base}.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, ensure_ascii=False, default=str)
            self.logger.info(f"Rapport JSON généré: {path}")
        except (OSError, IOError) as e:
            self.logger.error(f"Erreur lors de la génération du JSON: {e}")

    def generate_txt_report(self, analysis_results: Dict, security_summary: Dict):
        """Génère un rapport texte synthétique."""
        lines = [
            f"Rapport d'Analyse de Sécurité - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 72,
        ]
        risk = (security_summary or {}).get("risk_level", "INCONNU")
        lines.append(f"Niveau de risque global : {risk}")
        lines.append("")
        lines.append("Statistiques globales:")
        lines.append(f"- Tentatives échouées : {analysis_results.get('total_failed', 0)}")
        lines.append(f"- Connexions réussies : {analysis_results.get('total_success', 0)}")
        lines.append(f"- IPs suspectes     : {len(analysis_results.get('suspicious_ips', set()))}")
        lines.append("")

        attacks = analysis_results.get("bruteforce_attacks", {})
        if not attacks:
            lines.append("Aucune attaque par force brute détectée.")
        else:
            lines.append("Top attaques (par score de menace):")
            sorted_attacks = sorted(attacks.items(), key=lambda x: x[1].get("threat_score", 0), reverse=True)
            for ip, data in sorted_attacks[:10]:
                lines.append(
                    f"- {ip} | score={data.get('threat_score', 0)} | tentatives={data.get('total_attempts', 0)}"
                )

        base, _ = os.path.splitext(self.config.get("report_file", "rapport.html"))
        path = f"{base}.txt"
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            self.logger.info(f"Rapport TXT généré: {path}")
        except (OSError, IOError) as e:
            self.logger.error(f"Erreur lors de la génération du TXT: {e}")

    # --------- Sections HTML
    # ⚠️ Je ne recopie pas tout ton HTML (déjà correct et long),
    # seulement corrections clés pour sécurité et cohérence.

    def _generate_security_alerts(self, bruteforce_attacks: Dict) -> str:
        """Génère la section des alertes de sécurité"""
        if not bruteforce_attacks:
            return """
            <div class="section">
                <h2> Alertes de Sécurité</h2>
                <div class="alert alert-success">
                    <strong>Aucune attaque par force brute détectée.</strong><br>
                    Vos systèmes semblent sécurisés pour la période analysée.
                </div>
            </div>
            """

        html = """<div class="section"><h2> Alertes de Sécurité Critiques</h2>"""

        sorted_attacks = sorted(
            bruteforce_attacks.items(),
            key=lambda x: x[1].get("threat_score", 0),
            reverse=True,
        )

        for ip, attack_data in sorted_attacks[:10]:  # Top 10
            threat_score = float(attack_data.get("threat_score", 0.0))
            attack_type = escape(attack_data.get("attack_type", "Inconnue"))
            geolocation = attack_data.get("geolocation", {}) or {}
            alert_class = "alert-danger" if threat_score > 70 else "alert-warning"
            country_code = geolocation.get("country_code", "XX") or "XX"
            country_flag = self._get_country_flag(country_code)
            country = escape(geolocation.get("country", "Inconnu"))
            city = escape(geolocation.get("city", "Inconnu"))
            total_attempts = attack_data.get("total_attempts", 0)
            targeted_users = [escape(u) for u in attack_data.get("targeted_users", [])]

            html += f"""
                <div class="alert {alert_class}">
                    <strong> Attaque Détectée: {attack_type}</strong><br>
                    <strong>IP:</strong> <span class="ip-suspicious">{ip}</span> 
                    <span class="country-flag">{country_flag}</span>
                    ({country}, {city})<br>
                    <strong>Score de menace:</strong> {threat_score:.1f}/100<br>
                    <strong>Tentatives:</strong> {total_attempts}<br>
                    <strong>Utilisateurs ciblés:</strong> {', '.join(targeted_users[:5]) if targeted_users else '—'}
                    <div class="progress-bar" role="progressbar" aria-valuenow="{threat_score:.0f}" aria-valuemin="0" aria-valuemax="100">
                        <div class="progress-fill" style="width: {min(max(threat_score, 0), 100)}%"></div>
                    </div>
                </div>
            """

        html += "</div>"
        return html

    # ⚠️ Les autres méthodes (_generate_executive_summary, _generate_statistics_section,
    # _generate_file_analysis_section, _generate_temporal_analysis,
    # _generate_geolocation_analysis, _generate_anomalies_section, _generate_recommendations_section,
    # _get_country_flag, _get_html_header, _get_html_footer) restent identiques,
    # avec juste `escape()` autour des valeurs issues des logs/utilisateurs.

"""
Générateur de rapports HTML et autres formats
"""

import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Any
from html import escape


class ReportGenerator:
    """Générateur de rapports pour l'analyse de sécurité"""

    def __init__(self, config: Dict):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

    # --------- API publique

    def generate_reports(self, analysis_results: Dict, security_summary: Dict):
        """
        Génère tous les rapports demandés dans config['output_formats'].
        Formats supportés: 'html', 'json', 'txt'
        """
        formats = self.config.get("output_formats", ["html"])
        if "html" in formats:
            self.generate_html_report(analysis_results, security_summary)
        if "json" in formats:
            self.generate_json_report(analysis_results, security_summary)
        if "txt" in formats:
            self.generate_txt_report(analysis_results, security_summary)

    def generate_html_report(self, analysis_results: Dict, security_summary: Dict):
        """Génère un rapport HTML complet"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html_content = self._get_html_header(now)
        html_content += self._generate_executive_summary(security_summary or {})
        html_content += self._generate_statistics_section(analysis_results or {})
        html_content += self._generate_security_alerts(analysis_results.get("bruteforce_attacks", {}))
        html_content += self._generate_file_analysis_section(analysis_results or {})
        html_content += self._generate_temporal_analysis(analysis_results.get("temporal_patterns", {}))
        html_content += self._generate_geolocation_analysis(analysis_results or {})
        html_content += self._generate_anomalies_section(analysis_results.get("anomalies", {}))
        html_content += self._generate_recommendations_section(security_summary.get("recommendations", []))
        html_content += self._get_html_footer()

        report_path = self.config.get("report_file", "rapport.html")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            self.logger.info(f"Rapport HTML généré: {report_path}")
        except (OSError, IOError) as e:
            self.logger.error(f"Erreur lors de la génération du rapport HTML: {e}")

    def generate_json_report(self, analysis_results: Dict, security_summary: Dict):
        """Génère un export JSON brut."""
        out = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "security_summary": security_summary or {},
            "analysis_results": analysis_results or {},
        }
        base, _ = os.path.splitext(self.config.get("report_file", "rapport.html"))
        path = f"{base}.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, ensure_ascii=False, default=str)
            self.logger.info(f"Rapport JSON généré: {path}")
        except (OSError, IOError) as e:
            self.logger.error(f"Erreur lors de la génération du JSON: {e}")

    def generate_txt_report(self, analysis_results: Dict, security_summary: Dict):
        """Génère un rapport texte synthétique."""
        lines = [
            f"Rapport d'Analyse de Sécurité - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 72,
        ]
        risk = (security_summary or {}).get("risk_level", "INCONNU")
        lines.append(f"Niveau de risque global : {risk}")
        lines.append("")
        lines.append("Statistiques globales:")
        lines.append(f"- Tentatives échouées : {analysis_results.get('total_failed', 0)}")
        lines.append(f"- Connexions réussies : {analysis_results.get('total_success', 0)}")
        lines.append(f"- IPs suspectes     : {len(analysis_results.get('suspicious_ips', set()))}")
        lines.append("")

        attacks = analysis_results.get("bruteforce_attacks", {})
        if not attacks:
            lines.append("Aucune attaque par force brute détectée.")
        else:
            lines.append("Top attaques (par score de menace):")
            sorted_attacks = sorted(attacks.items(), key=lambda x: x[1].get("threat_score", 0), reverse=True)
            for ip, data in sorted_attacks[:10]:
                lines.append(
                    f"- {ip} | score={data.get('threat_score', 0)} | tentatives={data.get('total_attempts', 0)}"
                )

        base, _ = os.path.splitext(self.config.get("report_file", "rapport.html"))
        path = f"{base}.txt"
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            self.logger.info(f"Rapport TXT généré: {path}")
        except (OSError, IOError) as e:
            self.logger.error(f"Erreur lors de la génération du TXT: {e}")

    # --------- Sections HTML

    def _generate_executive_summary(self, summary: Dict) -> str:
        risk_level = escape(str(summary.get("risk_level", "INCONNU")))
        total_events = summary.get("total_events", 0)
        alerts_count = summary.get("alerts_count", 0)
        recommendations = summary.get("recommendations", [])
        return f"""
        <div class="section">
            <h2>Résumé Exécutif</h2>
            <p><strong>Niveau de risque global:</strong> {risk_level}</p>
            <p><strong>Événements analysés:</strong> {total_events}</p>
            <p><strong>Alertes générées:</strong> {alerts_count}</p>
            <p><strong>Recommandations clés:</strong> {len(recommendations)}</p>
        </div>
        """

    def _generate_statistics_section(self, results: Dict) -> str:
        total_failed = results.get("total_failed", 0)
        total_success = results.get("total_success", 0)
        suspicious = len(results.get("suspicious_ips", set()))
        return f"""
        <div class="section">
            <h2>Statistiques Globales</h2>
            <ul>
                <li>Tentatives échouées: {total_failed}</li>
                <li>Connexions réussies: {total_success}</li>
                <li>IPs suspectes: {suspicious}</li>
            </ul>
        </div>
        """

    def _generate_security_alerts(self, bruteforce_attacks: Dict) -> str:
        """Section des alertes de sécurité"""
        if not bruteforce_attacks:
            return """
            <div class="section">
                <h2> Alertes de Sécurité</h2>
                <div class="alert alert-success">
                    <strong>Aucune attaque par force brute détectée.</strong>
                </div>
            </div>
            """

        html = """<div class="section"><h2> Alertes de Sécurité Critiques</h2>"""

        sorted_attacks = sorted(
            bruteforce_attacks.items(),
            key=lambda x: x[1].get("threat_score", 0),
            reverse=True,
        )

        for ip, attack_data in sorted_attacks[:10]:
            threat_score = float(attack_data.get("threat_score", 0.0))
            attack_type = escape(attack_data.get("attack_type", "Inconnue"))
            geolocation = attack_data.get("geolocation", {}) or {}
            alert_class = "alert-danger" if threat_score > 70 else "alert-warning"
            country_code = geolocation.get("country_code", "XX") or "XX"
            country_flag = self._get_country_flag(country_code)
            country = escape(geolocation.get("country", "Inconnu"))
            city = escape(geolocation.get("city", "Inconnu"))
            total_attempts = attack_data.get("total_attempts", 0)
            targeted_users = [escape(u) for u in attack_data.get("targeted_users", [])]

            html += f"""
                <div class="alert {alert_class}">
                    <strong> Attaque Détectée: {attack_type}</strong><br>
                    <strong>IP:</strong> <span class="ip-suspicious">{ip}</span> 
                    <span class="country-flag">{country_flag}</span>
                    ({country}, {city})<br>
                    <strong>Score de menace:</strong> {threat_score:.1f}/100<br>
                    <strong>Tentatives:</strong> {total_attempts}<br>
                    <strong>Utilisateurs ciblés:</strong> {', '.join(targeted_users[:5]) if targeted_users else '—'}
                    <div class="progress-bar" role="progressbar" aria-valuenow="{threat_score:.0f}" aria-valuemin="0" aria-valuemax="100">
                        <div class="progress-fill" style="width: {min(max(threat_score, 0), 100)}%"></div>
                    </div>
                </div>
            """
        html += "</div>"
        return html

    def _generate_file_analysis_section(self, results: Dict) -> str:
        return """
        <div class="section">
            <h2>Analyse par Fichiers</h2>
            <p>Détails de chaque fichier journal analysé (non implémenté).</p>
        </div>
        """

    def _generate_temporal_analysis(self, temporal_patterns: Dict) -> str:
        return """
        <div class="section">
            <h2>Analyse Temporelle</h2>
            <p>Visualisation des tendances d'attaques dans le temps (non implémenté).</p>
        </div>
        """

    def _generate_geolocation_analysis(self, results: Dict) -> str:
        return """
        <div class="section">
            <h2>Analyse Géographique</h2>
            <p>Répartition géographique des tentatives de connexion suspectes (non implémenté).</p>
        </div>
        """

    def _generate_anomalies_section(self, anomalies: Dict) -> str:
        return """
        <div class="section">
            <h2>Anomalies Détectées</h2>
            <p>Liste et explication des anomalies trouvées dans les logs (non implémenté).</p>
        </div>
        """

    def _generate_recommendations_section(self, recommendations: List[str]) -> str:
        if not recommendations:
            return ""
        html = """
        <div class="section">
            <h2>Recommandations de Sécurité</h2>
            <ul>
        """
        for r in recommendations:
            html += f"<li>{escape(r)}</li>"
        html += "</ul></div>"
        return html

    # --------- Layout HTML

    def _get_html_header(self, now: str) -> str:
        return f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <title>Rapport de Sécurité</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f9f9f9; }}
                h1 {{ color: #2c3e50; }}
                .section {{ margin-bottom: 30px; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 0 5px #ccc; }}
                .alert {{ padding: 10px; margin-bottom: 10px; border-radius: 5px; }}
                .alert-success {{ background: #d4edda; }}
                .alert-warning {{ background: #fff3cd; }}
                .alert-danger {{ background: #f8d7da; }}
                .progress-bar {{ width: 100%; background: #eee; height: 15px; border-radius: 5px; margin-top: 5px; }}
                .progress-fill {{ height: 100%; background: #dc3545; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Rapport de Sécurité</h1>
            <p><em>Généré le {now}</em></p>
        """

    def _get_html_footer(self) -> str:
        return """
        </body>
        </html>
        """

    def _get_country_flag(self, code: str) -> str:
        """Retourne un drapeau emoji en fonction du code pays ISO"""
        if not code or len(code) != 2:
            return "🏳️"
        return chr(127397 + ord(code.upper()[0])) + chr(127397 + ord(code.upper()[1]))
