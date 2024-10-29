from django.contrib import admin
from .models import UserSession

class UserSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'session_key', 'created_at', 'last_activity', 'ip_address')
    search_fields = ('user__username', 'session_key', 'ip_address')
    list_filter = ('created_at', 'last_activity')

admin.site.register(UserSession, UserSessionAdmin)