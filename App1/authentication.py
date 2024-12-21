from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings

class CustomJWTAuthentication(JWTAuthentication):
    def get_raw_token(self, request):
        # Try to get token from cookies first
        access_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])
        if not access_token:
            # If no cookie found, fall back to Authorization header
            access_token = super().get_raw_token(request)
        return access_token
