from django.contrib.auth.models import User
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from rest_framework_simplejwt.exceptions import AuthenticationFailed
import jwt
from .models import Services  # Import your Vendor model


class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Retrieve the token from the cookie using the name specified in settings.py
        token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])
        if not token:
            raise AuthenticationFailed('Authentication token not found in cookies')

        # Use the standard JWTAuthentication method to decode and authenticate the token
        return self.authenticate_credentials(token)

    def authenticate_credentials(self, token):
        """
        Custom implementation of authenticate_credentials to handle the JWT token
        passed from the cookie and verify the credentials.
        """
        try:
            # Decode the JWT token using the secret key and algorithm defined in settings
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])

            # Extract user information from the payload
            user_id = payload.get('user_id')  # Ensure the user_id field is in your token's payload
            if not user_id:
                raise AuthenticationFailed('User ID not found in token')

            # Retrieve the user from the database
            user = self.get_user(user_id)
            if user is None:
                raise AuthenticationFailed('User not found')

            # Return the authenticated user and the token
            return (user, token)

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.DecodeError:
            raise AuthenticationFailed('Error decoding token')
        except User.DoesNotExist:
            raise AuthenticationFailed('User does not exist')
        except Exception as e:
            raise AuthenticationFailed(f'Authentication failed: {str(e)}')

    def get_user(self, user_id):
        """
        Helper method to get the user by ID.
        Adjust this method according to your project's User model.
        """
        from django.contrib.auth.models import User  # Or your custom user model
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None