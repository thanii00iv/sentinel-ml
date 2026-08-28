#!/usr/bin/env bash
# exit on error
set -o errexit

pip install -r requirements.txt

python manage.py collectstatic --no-input
python manage.py migrate

# Pre-train and serialize models during build step so requests load instantly
python -c "import django, os; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iml_core.settings'); django.setup(); from monitor.ml_model import retrain_all_models; retrain_all_models();"
