from django.apps import AppConfig
from django.db.models.signals import post_migrate


def ensure_default_superuser(sender, **kwargs):
    try:
        from django.contrib.auth.models import User
        user, created = User.objects.get_or_create(username='admin')
        if created:
            user.set_password('admin123')
            user.is_staff = True
            user.is_superuser = True
            user.save()
            print("[CyberOracle Intel] Default superuser 'admin' with password 'admin123' initialized.")
        elif not user.is_superuser or not user.is_staff:
            user.is_staff = True
            user.is_superuser = True
            user.save()
    except Exception:
        pass


class MonitorConfig(AppConfig):
    name = 'monitor'

    def ready(self):
        post_migrate.connect(ensure_default_superuser, sender=self)
