import json
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from monitor.models import RequestLog, IPRiskProfile, ThreatHuntFinding, PredictiveAlert
from monitor.detection import parse_device_info, detect_sqli, detect_xss, detect_path_traversal
from monitor.geoip import resolve_ip_geo
from monitor.ml_model import get_features, predict, predict_anomaly, retrain_all_models
from monitor.hunter import run_autonomous_threat_hunt
from monitor.prediction import predict_next_stage_and_asset


class SentinelMLComprehensiveTests(TestCase):
    def setUp(self):
        # Create test operator user
        self.username = 'testadmin'
        self.password = 'Project.4'
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
            is_staff=True,
            is_superuser=True
        )

        # Create baseline request logs and IP profiles for test assertions
        self.test_ip = '198.51.100.45'
        self.clean_ip = '192.168.1.100'

        for i in range(10):
            RequestLog.objects.create(
                ip_address=self.test_ip,
                method='POST',
                path='/login/',
                status_code=401,
                user_agent='Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15',
                is_sqli_suspect=(i % 2 == 0),
                is_brute_force_suspect=(i % 3 == 0),
                is_recon_suspect=(i % 4 == 0),
                is_xss_suspect=False,
                is_path_traversal_suspect=False,
                inferred_intent='SQL Injection Attack' if (i % 2 == 0) else 'Brute Force Authentication',
                entropy_score=3.8,
                request_rate=2.5,
                response_time_ms=45.2
            )

        self.profile = IPRiskProfile.objects.create(
            ip_address=self.test_ip,
            risk_score=85,
            sqli_count=5,
            brute_force_count=3,
            recon_count=2,
            fused_score=88.5,
            is_blocked=False
        )

        self.client = Client()

    # -------------------------------------------------------------
    # 1. Authentication & Security Gateway Tests
    # -------------------------------------------------------------
    def test_login_page_renders(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Security Clearance')

    def test_login_success_ajax(self):
        response = self.client.post(
            reverse('login'),
            json.dumps({'username': self.username, 'password': self.password}),
            content_type='application/json',
            HTTP_X_REQUESTED_WITH='XMLHttpRequest'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get('success'))
        self.assertEqual(data.get('redirect_url'), '/dashboard/')

    def test_login_failure_ajax(self):
        response = self.client.post(
            reverse('login'),
            json.dumps({'username': self.username, 'password': 'WrongPassword123'}),
            content_type='application/json',
            HTTP_X_REQUESTED_WITH='XMLHttpRequest'
        )
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertFalse(data.get('success'))
        self.assertIn('error', data)

    def test_protected_routes_redirect_unauthenticated(self):
        routes = ['home', 'threat_list', 'threat_hunting', 'attack_simulator', 'evaluation']
        for route_name in routes:
            response = self.client.get(reverse(route_name))
            self.assertEqual(response.status_code, 302, f"Route {route_name} did not redirect unauthenticated user.")
            self.assertIn('/login/', response.url)

    # -------------------------------------------------------------
    # 2. Public & Core SOC View Tests (Authenticated)
    # -------------------------------------------------------------
    def test_authenticated_soc_views(self):
        self.client.login(username=self.username, password=self.password)

        views_to_test = [
            ('landing', 200),
            ('home', 200),
            ('threat_list', 200),
            ('threat_hunting', 200),
            ('attack_simulator', 200),
            ('evaluation', 200),
        ]

        for view_name, expected_status in views_to_test:
            response = self.client.get(reverse(view_name))
            self.assertEqual(response.status_code, expected_status, f"View {view_name} returned {response.status_code}")

    def test_threat_journey_view(self):
        self.client.login(username=self.username, password=self.password)
        response = self.client.get(reverse('threat_journey', kwargs={'ip': self.test_ip}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.test_ip)

    # -------------------------------------------------------------
    # 3. REST API Endpoints Tests
    # -------------------------------------------------------------
    def test_threat_map_api(self):
        response = self.client.get(reverse('api_threat_map'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('markers', data)
        self.assertGreaterEqual(len(data['markers']), 1)

    def test_toggle_block_api(self):
        response = self.client.post(reverse('api_toggle_block', kwargs={'ip': self.test_ip}))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'SUCCESS')
        self.assertTrue(data['is_blocked'])

        # Toggle back
        response = self.client.post(reverse('api_toggle_block', kwargs={'ip': self.test_ip}))
        self.assertFalse(response.json()['is_blocked'])

    def test_run_hunt_api(self):
        response = self.client.post(reverse('api_hunt'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'SUCCESS')
        self.assertIn('findings_created', data)

    def test_simulation_api(self):
        sim_types = ['sqli', 'brute_force', 'recon', 'xss', 'path_traversal', 'normal', 'killchain']
        for sim in sim_types:
            response = self.client.post(
                reverse('api_simulate'),
                json.dumps({'sim_type': sim, 'ip': '198.51.100.99', 'count': 2}),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 200, f"Simulation {sim} failed.")
            data = response.json()
            self.assertEqual(data.get('status'), 'SUCCESS')

    def test_export_telemetry_csv_and_json(self):
        # CSV Export
        csv_res = self.client.get(reverse('api_export_telemetry', kwargs={'format_type': 'csv'}))
        self.assertEqual(csv_res.status_code, 200)
        self.assertEqual(csv_res['Content-Type'], 'text/csv')

        # JSON Export
        json_res = self.client.get(reverse('api_export_telemetry', kwargs={'format_type': 'json'}))
        self.assertEqual(json_res.status_code, 200)
        self.assertEqual(json_res['Content-Type'], 'application/json')

    # -------------------------------------------------------------
    # 4. Canary Honeypot Decoy Traps Tests
    # -------------------------------------------------------------
    def test_honeypot_traps(self):
        traps = ['honeypot_env', 'honeypot_sql', 'honeypot_git', 'honeypot_wp', 'honeypot_api', 'honeypot_pma']
        for idx, trap in enumerate(traps):
            trap_ip = f'198.51.100.{100 + idx}'
            response = self.client.get(reverse(trap), REMOTE_ADDR=trap_ip)
            # Honeypot immediately blocks and responds with 403 Forbidden
            self.assertEqual(response.status_code, 403)
            self.assertIn('Honeypot Trap Engaged', response.content.decode())

            # Verify that the IP profile was automatically created and quarantined
            profile = IPRiskProfile.objects.filter(ip_address=trap_ip).first()
            self.assertIsNotNone(profile)
            self.assertTrue(profile.is_blocked)

            # Subsequent request from the quarantined IP is blocked by middleware firewall
            blocked_response = self.client.get('/landing/', REMOTE_ADDR=trap_ip)
            self.assertEqual(blocked_response.status_code, 403)

    # -------------------------------------------------------------
    # 5. Device Fingerprinting & GeoIP Tests
    # -------------------------------------------------------------
    def test_parse_device_info(self):
        iphone_ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'
        res = parse_device_info(iphone_ua)
        self.assertEqual(res['device_name'], 'Apple iPhone')
        self.assertEqual(res['device_type'], 'Mobile')
        self.assertEqual(res['browser'], 'Apple Safari')

        android_ua = 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36'
        res_android = parse_device_info(android_ua)
        self.assertEqual(res_android['device_name'], 'Android Smartphone')
        self.assertEqual(res_android['browser'], 'Google Chrome')

    def test_resolve_ip_geo(self):
        geo = resolve_ip_geo('127.0.0.1')
        self.assertIn('lat', geo)
        self.assertIn('lng', geo)
        self.assertIn('city', geo)
        self.assertIn('country', geo)

    # -------------------------------------------------------------
    # 6. ML Models & Prediction Tests
    # -------------------------------------------------------------
    def test_ml_pipeline(self):
        log = RequestLog.objects.first()
        features = get_features(log)
        self.assertEqual(len(features), 12)

        # Predict anomaly
        is_anom, raw_score, norm_score = predict_anomaly(log)
        self.assertIsInstance(is_anom, bool)
        self.assertIsInstance(norm_score, float)

        # Markov next stage prediction
        next_stage, asset, conf, score, reason, rec = predict_next_stage_and_asset(self.profile)
        self.assertIsNotNone(next_stage)
        self.assertIsNotNone(asset)
