from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

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
