from django.urls import path
from .views import LoginView, CookieTokenRefreshView, LogoutView, LogoutAllView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', CookieTokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('logout/all/', LogoutAllView.as_view(), name='logout_all'),
]
