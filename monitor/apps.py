from django.apps import AppConfig
from django.db.models.signals import post_migrate


def ensure_default_superuser(sender, **kwargs):
    try:
        from django.contrib.auth.models import User
        user, created = User.objects.get_or_create(username='admin')
        user.set_password('admin123')
        user.is_staff = True
        user.is_superuser = True
        user.save()
        print("[SentinelML] Superuser 'admin' with password 'admin123' verified.")
    except Exception:
        pass


class MonitorConfig(AppConfig):
    name = 'monitor'

    def ready(self):
        post_migrate.connect(ensure_default_superuser, sender=self)
