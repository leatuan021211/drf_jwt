from django.conf import settings
from django.db import models
from django.utils import timezone
from rest_framework_simplejwt.tokens import OutstandingToken

class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f'{self.user.username} - {self.session_key}'


class TokenRequestLog(models.Model):
    token = models.ForeignKey(OutstandingToken, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [
            models.Index(fields=['token', 'timestamp']),
        ]