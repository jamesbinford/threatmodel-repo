"""
Development settings for Threat Model Repository.
"""
import os
from dotenv import load_dotenv
from .base import *

load_dotenv()

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-dev-key-change-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
    if host.strip()
]

# Database - use DB_ENGINE=mysql or DB_ENGINE=postgresql when DB_NAME is set,
# otherwise fall back to SQLite for easy local dev.
if os.getenv('DB_NAME'):
    db_engine = os.getenv('DB_ENGINE', 'postgresql').lower()
    if db_engine == 'mysql':
        import pymysql
        pymysql.install_as_MySQLdb()

    DATABASES = {
        'default': {
            'ENGINE': f'django.db.backends.{db_engine}',
            'NAME': os.getenv('DB_NAME'),
            'USER': os.getenv('DB_USER', 'root' if db_engine == 'mysql' else 'postgres'),
            'PASSWORD': os.getenv('DB_PASSWORD', ''),
            'HOST': os.getenv('DB_HOST', 'localhost'),
            'PORT': os.getenv('DB_PORT', '3306' if db_engine == 'mysql' else '5432'),
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# File storage - use local filesystem in development
DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'
