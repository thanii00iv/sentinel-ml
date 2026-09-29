import os
import csv
from datetime import datetime
from django.core.management.base import BaseCommand
from django.conf import settings
from django.utils import timezone
from monitor.models import RequestLog, IPRiskProfile
from monitor.detection import calculate_entropy
from monitor.fusion_engine import evaluate_and_fuse_profile


class Command(BaseCommand):
    help = "Imports network flow dataset into RequestLog telemetry and updates IPRiskProfile records."

    def add_arguments(self, parser):
        parser.add_argument(
            '--file',
            type=str,
            default=os.path.join(settings.BASE_DIR, 'monitor', 'data', 'network_traffic.csv'),
            help='Path to the network traffic CSV file'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear previously imported dataset records before importing'
        )

    def handle(self, *args, **options):
        csv_file = options['file']
        if not os.path.exists(csv_file):
            self.stderr.write(self.style.ERROR(f"File not found: {csv_file}"))
            return

        if options['clear']:
            deleted = RequestLog.objects.filter(user_agent__startswith="NetworkFlow/").delete()
            self.stdout.write(f"Cleared {deleted[0]} previous dataset logs.")

        self.stdout.write(f"Reading dataset from {csv_file}...")

        logs_to_create = []
        ip_stats = {}

        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                src_ip = row.get('Source_IP', '').strip()
                if not src_ip:
                    continue

                ts_str = row.get('Timestamp', '').strip()
                try:
                    dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                    ts = timezone.make_aware(dt, timezone.get_current_timezone())
                except Exception:
                    ts = timezone.now()

                proto = row.get('Protocol', 'TCP').strip()
                flags = row.get('Flags', '').strip()
                pkt_len = int(float(row.get('Packet_Length', 0)))
                duration = float(row.get('Duration', 0.0))
                src_port = row.get('Source_Port', '0').strip()
                dst_port = row.get('Destination_Port', '80').strip()
                flow_pps = float(row.get('Flow_Packets/s', 1.0))
                attack_type = row.get('Attack_Type', 'Normal').strip()
                is_attack = attack_type.lower() != 'normal'

                if attack_type == 'Brute Force':
                    path = f"/login/?port={dst_port}"
                    method = "POST"
                    status_code = 401
                    is_login = True
                    login_succ = False
                    is_brute = True
                    is_recon = False
                    is_path_trav = False
                    intent = "Credential Guessing / Brute-Force"
                elif attack_type == 'DDoS':
                    path = f"/api/v1/stream/?port={dst_port}"
                    method = proto if proto in ('GET', 'POST') else 'POST'
                    status_code = 503
                    is_login = False
                    login_succ = None
                    is_brute = False
                    is_recon = True  # Volume anomaly / scanner
                    is_path_trav = False
                    intent = "DDoS Flood Attack"
                elif attack_type == 'Ransomware':
                    path = f"/internal/data/export/?vault={dst_port}"
                    method = "POST"
                    status_code = 403
                    is_login = False
                    login_succ = None
                    is_brute = False
                    is_recon = False
                    is_path_trav = True
                    intent = "Ransomware C2 Exfiltration"
                else:  # Normal
                    path = f"/index.html?svc={dst_port}"
                    method = "GET"
                    status_code = 200
                    is_login = False
                    login_succ = None
                    is_brute = False
                    is_recon = False
                    is_path_trav = False
                    intent = "Legitimate Traffic"

                resp_time = round(duration * 1000.0, 2)
                entropy = calculate_entropy(f"{proto}{flags}{pkt_len}{dst_port}")
                ua = f"NetworkFlow/{proto} ({flags}; Len={pkt_len}; Ports={src_port}->{dst_port})"

                log = RequestLog(
                    ip_address=src_ip,
                    method=method,
                    path=path,
                    status_code=status_code,
                    user_agent=ua,
                    response_time_ms=resp_time,
                    is_login_attempt=is_login,
                    login_success=login_succ,
                    is_brute_force_suspect=is_brute,
                    is_sqli_suspect=False,
                    is_recon_suspect=is_recon,
                    is_xss_suspect=False,
                    is_path_traversal_suspect=is_path_trav,
                    inferred_intent=intent,
                    entropy_score=entropy,
                    request_rate=flow_pps,
                    timestamp=ts
                )
                logs_to_create.append(log)

                # Aggregate IP metrics
                if src_ip not in ip_stats:
                    ip_stats[src_ip] = {
                        'brute': 0, 'recon': 0, 'path_trav': 0, 'total': 0, 'latest_log': None
                    }
                ip_stats[src_ip]['total'] += 1
                if is_brute:
                    ip_stats[src_ip]['brute'] += 1
                if is_recon:
                    ip_stats[src_ip]['recon'] += 1
                if is_path_trav:
                    ip_stats[src_ip]['path_trav'] += 1
                ip_stats[src_ip]['latest_log'] = log

        self.stdout.write(f"Bulk saving {len(logs_to_create)} RequestLog records...")
        RequestLog.objects.bulk_create(logs_to_create, batch_size=500)
        self.stdout.write(self.style.SUCCESS(f"Successfully ingested {len(logs_to_create)} network flow logs."))

        # Update IPRiskProfiles
        self.stdout.write("Updating IPRiskProfile records and computing ICMF fusion scores...")
        for ip, stats in ip_stats.items():
            profile, _ = IPRiskProfile.objects.get_or_create(ip_address=ip)
            profile.brute_force_count += stats['brute']
            profile.recon_count += stats['recon']
            profile.path_traversal_count += stats['path_trav']
            profile.risk_score = min(100, (profile.brute_force_count * 5 + profile.recon_count * 4 + profile.path_traversal_count * 6))
            if profile.risk_score >= 70:
                profile.is_blocked = True
            profile.save()
            evaluate_and_fuse_profile(profile, latest_log=stats['latest_log'])
            self.stdout.write(f"  - Profile updated for {ip}: Risk={profile.risk_score}, Threat={profile.threat_level()}")

        self.stdout.write(self.style.SUCCESS("Dataset ingestion and IPRiskProfile fusion complete!"))
