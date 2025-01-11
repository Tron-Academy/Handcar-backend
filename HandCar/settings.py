"""
Django settings for HandCar project.

Generated by 'django-admin startproject' using Django 5.1.1.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""
import os

from django.core.exceptions import ImproperlyConfigured

from . import keys
from pathlib import Path



import cloudinary
from decouple import config

cloudinary.config(
    cloud_name=config('CLOUDINARY_CLOUD_NAME'),
    api_key=config('CLOUDINARY_API_KEY'),
    api_secret=config('CLOUDINARY_API_SECRET')
)



# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-g*6$8q350_^v7k=e-%ky4$&nn48ds8=&mvpqi5&)j=d_n5b(b!'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*', '127.0.0.1', 'localhost', 'handcar-backend-1.onrender.com' ]




CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
]
CORS_ALLOW_CREDENTIALS = True



# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'App1',
    'rest_framework',
    'corsheaders',
    'rest_framework_simplejwt.token_blacklist',
    # 'channels'
]


# ASGI_APPLICATION = 'your_project.routing.application'
#
# CHANNEL_LAYERS = {
#     'default': {
#         'BACKEND': 'channels_redis.core.RedisChannelLayer',
#         'CONFIG': {
#             "hosts": [('127.0.0.1', 6379)],
#         },
#     },
# }



REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'App1.authentication.CustomJWTAuthentication',  # Check cookies first, then fallback
        'rest_framework_simplejwt.authentication.JWTAuthentication',  # Only checks headers
    ),
}



from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),  # Adjust as needed
    'REFRESH_TOKEN_LIFETIME': timedelta(weeks=4),     # Adjust as needed
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'AUTH_COOKIE': 'access_token',                    # Name of the access token cookie
    'AUTH_COOKIE_REFRESH': 'refresh_token',           # Name of the refresh token cookie
    'AUTH_COOKIE_SECURE': True,                      # Set to True in production
    'AUTH_COOKIE_HTTP_ONLY': True,                    # Cookie is HTTP only
    'AUTH_COOKIE_PATH': '/',                          # Cookie path
    'AUTH_COOKIE_SAMESITE': 'None',                  # Adjust based on your needs (None, Lax, Strict)
    'AUTH_COOKIE_EXPIRES': timedelta(days=30),        # Set cookie expiration to 30 days
}




MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware'
]

ROOT_URLCONF = 'HandCar.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'HandCar.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases
#
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'postgres',
#         'USER': 'postgres',
#         'PASSWORD': 'admin',
#         'HOST': 'localhost',
#         'PORT': '5432',
#
#     }
#
# }

# import dj_database_url
# from decouple import config
# DATABASES = {
#     'default': dj_database_url.config(
#         default=config('DATABASE_URL')  # DATABASE_URL environment variable
#     )
# }
#
# print(config('DATABASE_URL'))  # Check if it prints the correct value
import dj_database_url
from decouple import config

# Add error handling and default value
DATABASE_URL = config('DATABASE_URL', default=None)
if not DATABASE_URL:
    raise ValueError("No DATABASE_URL set in environment")

print(f"Attempting to connect to: {DATABASE_URL}")  # Debug print

DATABASES = {
    'default': dj_database_url.parse(DATABASE_URL)
}



# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'


# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


TWILIO_ACCOUNT_SID = keys.ACCOUNT_SID
TWILIO_AUTH_TOKEN = keys.AUTH_TOKEN
TWILIO_PHONE_NUMBER = keys.PHONE_NUMBER



EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'parvathynair186@gmail.com'  # Your email address
EMAIL_HOST_PASSWORD = 'wkxv jmop yrha ldnq'  # Your email password
DEFAULT_FROM_EMAIL = 'parvathynair186@gmail.com'  # Default sender email


CORS_ALLOWED_ORIGINS = [
    'http://localhost:5173',
    "http://localhost:3000",
]

CORS_EXPOSE_HEADERS = ['Content-Type', 'X-CSRFToken']



TIME_ZONE = 'Asia/Kolkata'  # Replace with your preferred time zone
USE_TZ = True
