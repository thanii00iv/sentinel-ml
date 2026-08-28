#!/usr/bin/env bash
# exit on error
set -o errexit

pip install -r requirements.txt

python manage.py collectstatic --no-input
python manage.py migrate

# Remove legacy pickle files so models are built fresh inside Render's Python environment
rm -f monitor/rf_model.pkl monitor/isolation_forest.pkl

# Train fresh models natively inside Render's Python environment to eliminate version warnings
python -c "import django, os, warnings; warnings.filterwarnings('ignore'); os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iml_core.settings'); django.setup(); from monitor.ml_model import retrain_all_models; retrain_all_models();"
