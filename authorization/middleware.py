import datetime
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.tokens import OutstandingToken
from .models import TokenRequestLog


class JWTAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip token validation for login and refresh endpoints
        if not request.path.startswith('/api/auth/login/') and not request.path.startswith('/api/auth/refresh/') and not request.path.startswith('/admin/'):
            auth = JWTAuthentication()
            try:
                # Extract the token from the Authorization header
                auth_header = request.META.get('HTTP_AUTHORIZATION')
                if auth_header:
                    token = auth_header.split(' ')[1]  # Get the token from "Bearer <token>"
                    auth.get_validated_token(token)
                else:
                    raise AuthenticationFailed('Authorization header not present')
            except Exception as e:
                raise AuthenticationFailed('Invalid token') from e

        response = self.get_response(request)
        return response
    

class RateLimitMiddleware:
    RATE_LIMIT = 10  # Maximum 10 requests per second

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        if refresh_token:
            try:
                # Check the number of requests made by this token in the last second
                token = OutstandingToken.objects.get(token=refresh_token)
                now = timezone.now()
                one_second_ago = now - datetime.timedelta(seconds=1)

                # Count recent requests for this token
                recent_requests = TokenRequestLog.objects.filter(
                    token=token,
                    timestamp__gte=one_second_ago
                ).count()

                if recent_requests >= self.RATE_LIMIT:
                    # Revoke the token if rate limit is exceeded
                    BlacklistedToken.objects.get_or_create(token=token)
                    response = Response({'detail': 'Token has been revoked due to excessive requests.'},
                                        status=status.HTTP_429_TOO_MANY_REQUESTS)
                    response.delete_cookie('refresh_token')
                    return response

                # Log the current request
                TokenRequestLog.objects.create(token=token, timestamp=now)

            except OutstandingToken.DoesNotExist:
                pass  # Handle the case where token isn't found gracefully

        return self.get_response(request)
