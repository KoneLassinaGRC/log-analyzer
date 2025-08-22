#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script principal pour l'analyseur de logs de sécurité
"""

import argparse
import sys
import os
from pathlib import Path
import logging

from patterns import PatternManager
# Rendre importables les modules locaux (quand exécuté en script)
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from log_analyzer import LogAnalyzer


def setup_argument_parser():
    """Configure l'analyseur d'arguments de ligne de commande"""
    parser = argparse.ArgumentParser(
        description="Analyseur de logs de sécurité - Détection d'intrusions et d'anomalies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python main.py                           # Analyse avec configuration par défaut
  python main.py -d /var/log               # Spécifier le dossier de logs
  python main.py -o rapport_custom.html    # Fichier de sortie personnalisé
  python main.py -t 10 --no-geo            # Seuil personnalisé sans géolocalisation
  python main.py -v                        # Mode verbose
        """
    )

    parser.add_argument(
        '-d', '--log-dir',
        type=str,
        default='logs',
        help='Dossier contenant les fichiers de logs (défaut: logs)'
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        default='rapport.html',
        help='Fichier de rapport de sortie (défaut: rapport.html)'
    )

    parser.add_argument(
        '-c', '--config',
        type=str,
        default='config.json',
        help='Fichier de configuration (défaut: config.json)'
    )

    parser.add_argument(
        '-t', '--threshold',
        type=int,
        help='Seuil pour la détection de force brute (défaut: 5)'
    )

    parser.add_argument(
        '-w', '--time-window',
        type=int,
        help='Fenêtre temporelle en minutes (défaut: 60)'
    )

    parser.add_argument(
        '--no-geo',
        action='store_true',
        help='Désactiver la géolocalisation des IPs'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Mode verbose - affichage détaillé'
    )

    parser.add_argument(
        '--format',
        choices=['html', 'json', 'txt'],
        default='html',
        help='Format de sortie du rapport (défaut: html)'
    )

    parser.add_argument(
        '--test-patterns',
        action='store_true',
        help="Tester les patterns de reconnaissance sur des logs d'exemple"
    )

    return parser


def validate_arguments(args):
    """Valide les arguments fournis"""
    errors = []

    # Vérifier que le dossier de logs existe (sauf en mode test-patterns)
    if not args.test_patterns and not Path(args.log_dir).exists():
        errors.append(f"Le dossier de logs '{args.log_dir}' n'existe pas")

    # Vérifier les valeurs numériques
    if args.threshold is not None and args.threshold < 1:
        errors.append("Le seuil doit être supérieur à 0")

    if args.time_window is not None and args.time_window < 1:
        errors.append("La fenêtre temporelle doit être supérieure à 0")

    # Vérifier/Créer le dossier de sortie
    output_path = Path(args.output)
    output_dir = output_path.parent if output_path.suffix else Path('.')
    if not output_dir.exists():
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            errors.append(f"Impossible de créer le dossier de sortie '{output_dir}'")

    return errors


def print_banner():
    """Affiche la bannière de l'application"""
    banner = r"""
╔═══════════════════════════════════════════════════════════════╗
║                    🛡️ ANALYSEUR DE LOGS DE SÉCURITÉ           ║
║                                                               ║
║     Détection d'intrusions & Analyse comportementale          ║
║                        Version 2.0.0                          ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def test_log_patterns():
    """Teste les patterns de reconnaissance avec des exemples"""
    # Import local (évite les imports inutiles si non utilisé)
    from patterns import PatternManager

    print("🧪 Test des patterns de reconnaissance...")

    # Logs d'exemple
    test_logs = [
        "Aug 21 10:15:32 server sshd[12345]: Failed password for admin from 192.168.1.100",
        "Aug 21 10:16:45 server sshd[12346]: Accepted password for user1 from 10.0.0.50",
        "Aug 21 10:17:20 server sshd[12347]: Invalid user hacker from 203.0.113.42",
        "2025-08-21 10:18:30 Failed login attempt for user root from 203.0.113.42",
        '192.168.1.200 - - [21/Aug/2025:10:19:45] "GET /admin HTTP/1.1" 401',
        'Aug 21 10:20:15 server ftpd: FAIL LOGIN: user="test" rhost=203.0.113.42',
        "Ligne non reconnue qui ne correspond à aucun pattern"
    ]

    pattern_manager = PatternManager()
    results = pattern_manager.test_patterns(test_logs)

    print(f"\n Résultats des tests:")
    print(f"    Lignes reconnues: {len(results['matched'])}")
    print(f"    Lignes non reconnues: {len(results['unmatched'])}")

    if results['matched']:
        print("\n Patterns utilisés:")
        for pattern, count in results['pattern_usage'].items():
            print(f"   - {pattern}: {count} fois")

    if results['unmatched']:
        print("\n⚠ Lignes non reconnues:")
        for line in results['unmatched']:
            print(f"   - {line[:80]}...")


def _derive_output_path_for_format(base_output: str, fmt: str) -> Path:
    """
    Retourne le chemin de sortie attendu pour l'affichage utilisateur en fonction du format.
    - Si l'extension ne correspond pas au format choisi, on l'ajuste.
    """
    p = Path(base_output)
    ext_map = {'html': '.html', 'json': '.json', 'txt': '.txt'}

    wanted_ext = ext_map.get(fmt, '.html')
    if p.suffix.lower() != wanted_ext:
        p = p.with_suffix(wanted_ext)
    return p


def main():
    """Fonction principale"""
    print_banner()

    # Parser les arguments
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Configurer un logging minimal côté CLI (utile si __init__ échoue avant la config interne)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='[%(levelname)s] %(message)s'
    )

    # Mode test des patterns
    if args.test_patterns:
        test_log_patterns()
        return 0

    # Valider les arguments
    errors = validate_arguments(args)
    if errors:
        print(" Erreurs dans les arguments:")
        for error in errors:
            print(f"   - {error}")
        return 1

    try:
        print(" Initialisation de l'analyseur...")

        # Créer l'analyseur avec la config fournie
        analyzer = LogAnalyzer(args.config)

        # Mettre à jour la configuration avec les arguments CLI
        # (Cette méthode doit exister côté ConfigManager)
        analyzer.config_manager.update_from_args(args)

        # Informer des chemins/format effectifs
        out_path_for_format = _derive_output_path_for_format(args.output, args.format)

        print(f" Analyse du dossier: {args.log_dir}")
        print(f" Format du rapport : {args.format}")
        print(f" Rapport de sortie: {out_path_for_format}")

        # Lancer l'analyse complète
        print("\n Analyse en cours...")
        results = analyzer.run_analysis()

        # Afficher un résumé
        print("\n" + "=" * 60)
        print(" RÉSUMÉ DE L'ANALYSE")
        print("=" * 60)
        print(f" Total tentatives échouées: {results.get('total_failed', 0)}")
        print(f" Total connexions réussies: {results.get('total_success', 0)}")
        print(f" IPs suspectes détectées: {len(results.get('suspicious_ips', set()))}")
        print(f" Attaques par force brute: {len(results.get('bruteforce_attacks', {}))}")

        # Afficher les attaques les plus dangereuses
        bruteforce_attacks = results.get('bruteforce_attacks', {})
        if bruteforce_attacks:
            print("\n TOP 5 DES ATTAQUES LES PLUS DANGEREUSES:")
            sorted_attacks = sorted(
                bruteforce_attacks.items(),
                key=lambda x: x[1].get('threat_score', 0),
                reverse=True
            )

            for i, (ip, attack_data) in enumerate(sorted_attacks[:5], 1):
                score = attack_data.get('threat_score', 0)
                attempts = attack_data.get('total_attempts', 0)
                attack_type = attack_data.get('attack_type', 'unknown')
                geolocation = attack_data.get('geolocation', {})
                country = geolocation.get('country', 'Inconnu')

                print(f"   {i}.  {ip} ({country})")
                print(f"       Score: {score:.1f}/100 | Tentatives: {attempts} | Type: {attack_type}")

        # Afficher les recommandations critiques
        security_summary = results.get('security_summary', {})
        recommendations = security_summary.get('recommendations', [])
        if recommendations:
            print("\n🛡️ RECOMMANDATIONS PRIORITAIRES:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"   {i}. {rec}")

        print("\n Analyse terminée avec succès!")
        print(f" 📄 Rapport détaillé disponible: {out_path_for_format}")

        return 0

    except KeyboardInterrupt:
        print("\n\n Analyse interrompue par l'utilisateur")
        return 1
    except Exception as e:
        print(f"\n❌ Erreur lors de l'analyse: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
