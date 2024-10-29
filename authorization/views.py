from rest_framework import status
from rest_framework import generics
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import OutstandingToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.exceptions import TokenError
from .serializers import LoginSerializer
from .models import UserSession 
import logging

logger = logging.getLogger(__name__)

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        ip_address = request.META.get('REMOTE_ADDR')

        # Log login request
        logger.info(f'User {user.username} logged in from {ip_address}')

        # Store session
        UserSession.objects.create(user=user, session_key=str(refresh), ip_address=ip_address)

        # Set HttpOnly cookie for refresh token
        response = Response({
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        
        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            httponly=True,
            samesite='Lax',
        )

        return response
    

class CookieTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        # Read the refresh token from the cookie
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return Response({'refresh': 'This field is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Create a custom request object to use with the parent class method
        request.data['refresh'] = refresh_token

        try:
            return super().post(request, *args, **kwargs)
        except TokenError:
            return Response({'refresh': 'Token is invalid or expired.'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            # Get the refresh token from the cookie
            refresh_token = request.COOKIES.get('refresh_token')
            if refresh_token:
                # Blacklist the token
                token = OutstandingToken.objects.get(token=refresh_token)
                BlacklistedToken.objects.create(token=token)

            response = Response(status=status.HTTP_205_RESET_CONTENT)
            response.delete_cookie('refresh_token')
            return response
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
