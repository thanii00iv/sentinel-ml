#!/usr/bin/env bash
# exit on error
set -o errexit

pip install -r requirements.txt

python manage.py collectstatic --no-input
python manage.py migrate

# Guarantee superuser admin:admin123 exists on cloud deployments
python -c "import django, os; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iml_core.settings'); django.setup(); from django.contrib.auth.models import User; u, _ = User.objects.get_or_create(username='admin'); u.set_password('admin123'); u.is_staff = True; u.is_superuser = True; u.save(); print('Cloud deployment: superuser admin:admin123 ready.')"

# Remove legacy pickle files so models are built fresh inside Render's Python environment
rm -f monitor/rf_model.pkl monitor/isolation_forest.pkl

# Train fresh models natively inside Render's Python environment to eliminate version warnings
python -c "import django, os, warnings; warnings.filterwarnings('ignore'); os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iml_core.settings'); django.setup(); from monitor.ml_model import retrain_all_models; retrain_all_models();"
