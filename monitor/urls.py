from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # Authentication
    path('login/', views.login_view, name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),

    # Root & Public Landing Page
    path('', views.root_entry, name='root'),
    path('landing/', views.landing, name='landing'),

    # Core SOC Pages
    path('dashboard/', views.home, name='home'),
    path('threats/', views.threat_list, name='threat_list'),
    path('threats/<str:ip>/', views.threat_journey, name='threat_journey'),
    path('hunting/', views.threat_hunting, name='threat_hunting'),
    path('simulator/', views.attack_simulator, name='attack_simulator'),
    path('evaluation/', views.evaluation, name='evaluation'),

    # REST APIs & Live Feeds
    path('api/hunt/', views.run_hunt_api, name='api_hunt'),
    path('api/simulate/', views.run_simulation_api, name='api_simulate'),
    path('api/toggle-block/<str:ip>/', views.toggle_ip_block, name='api_toggle_block'),
    path('api/retrain-model/', views.retrain_model_api, name='api_retrain_model'),
    path('api/export/<str:format_type>/', views.export_telemetry, name='api_export_telemetry'),
    path('api/threat-map/', views.threat_map_api, name='api_threat_map'),
    path('api/live-stream/', views.live_stream_api, name='api_live_stream'),

    # Canary Honeypot Decoy Traps
    path('.env', views.honeypot_trap, name='honeypot_env'),
    path('backup.sql', views.honeypot_trap, name='honeypot_sql'),
    path('.git/config', views.honeypot_trap, name='honeypot_git'),
    path('wp-login.php', views.honeypot_trap, name='honeypot_wp'),
    path('api/v1/internal/config', views.honeypot_trap, name='honeypot_api'),
    path('phpmyadmin/', views.honeypot_trap, name='honeypot_pma'),
]