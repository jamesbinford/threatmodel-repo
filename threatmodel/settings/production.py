"""
Production settings for Threat Model Repository.
AWS 3-tier deployment configuration (ALB + EC2 + RDS PostgreSQL).
"""
import os
from dotenv import load_dotenv
from .base import *
from .env import env_bool, env_int

load_dotenv()

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")

DEBUG = env_bool(os.environ, 'DEBUG', default=False)

ALLOWED_HOSTS = [h.strip() for h in os.environ.get('ALLOWED_HOSTS', '').split(',') if h.strip()]

# Database - PostgreSQL (RDS)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'threatmodel'),
        'USER': os.environ.get('DB_USER', 'threatmodel'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
        'OPTIONS': {
            'connect_timeout': 10,
        },
    }
}

# AWS S3 Storage via IAM Instance Profile (no access keys needed)
AWS_STORAGE_BUCKET_NAME = os.environ.get('AWS_STORAGE_BUCKET_NAME')

if AWS_STORAGE_BUCKET_NAME:
    AWS_S3_REGION_NAME = os.environ.get('AWS_S3_REGION_NAME', 'us-east-1')
    AWS_S3_CUSTOM_DOMAIN = f'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com'
    AWS_DEFAULT_ACL = 'private'
    AWS_S3_OBJECT_PARAMETERS = {
        'CacheControl': 'max-age=86400',
    }
    STORAGES = {
        "default": {
            "BACKEND": "storages.backends.s3boto3.S3Boto3Storage",
        },
        "staticfiles": {
            "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
        },
    }
else:
    STORAGES = {
        "default": {
            "BACKEND": "django.core.files.storage.FileSystemStorage",
        },
        "staticfiles": {
            "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
        },
    }

# Security settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'

SECURE_SSL_REDIRECT = env_bool(os.environ, 'SECURE_SSL_REDIRECT', default=True)
SESSION_COOKIE_SECURE = env_bool(os.environ, 'SESSION_COOKIE_SECURE', default=True)
CSRF_COOKIE_SECURE = env_bool(os.environ, 'CSRF_COOKIE_SECURE', default=True)
SECURE_HSTS_SECONDS = env_int(os.environ, 'SECURE_HSTS_SECONDS', default=31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool(os.environ, 'SECURE_HSTS_INCLUDE_SUBDOMAINS', default=True)
SECURE_HSTS_PRELOAD = env_bool(os.environ, 'SECURE_HSTS_PRELOAD', default=True)

if env_bool(os.environ, 'SECURE_PROXY_SSL_HEADER_ENABLED', default=False):
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

UPLOAD_MALWARE_SCANNER = os.environ.get('UPLOAD_MALWARE_SCANNER') or None

ENTRA_TENANT_ID = os.environ.get('ENTRA_TENANT_ID', '')
ENTRA_ISSUER = os.environ.get('ENTRA_ISSUER') or (
    f'https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0' if ENTRA_TENANT_ID else ''
)
ENTRA_AUDIENCE = os.environ.get('ENTRA_AUDIENCE', '')
ENTRA_JWKS_URL = os.environ.get('ENTRA_JWKS_URL') or (
    f'https://login.microsoftonline.com/{ENTRA_TENANT_ID}/discovery/v2.0/keys' if ENTRA_TENANT_ID else ''
)
ENTRA_REQUIRED_ROLES = [
    role.strip()
    for role in os.environ.get('ENTRA_REQUIRED_ROLES', 'ThreatModel.Submit,ThreatModel.Admin').split(',')
    if role.strip()
]

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.environ.get('LOG_FILE', '/var/log/threatmodel/django.log'),
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}
