"""
Django settings for LogDetection project.
"""

from pathlib import Path
import os
from decouple import config, Csv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Media settings
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('DJANGO_SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=Csv())

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'log_ingestion',
    'threat_detection',
    'incident_detection',
    'channels',  # For WebSockets
    'alerts',
    'reports',
    'authentication',
    'smtp_integration',
    'rest_framework',
    'siem',
    'frontend',
    'analytics',
    'ai_analytics',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'LogDetection.middleware.NotificationMiddleware',
]

ROOT_URLCONF = 'LogDetection.urls'

# Make sure this part of your settings includes the frontend directory
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates'),
            os.path.join(BASE_DIR, 'frontend'),
            os.path.join(BASE_DIR, 'frontend/admin'),
            os.path.join(BASE_DIR, 'frontend/templates'),
        ],
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

WSGI_APPLICATION = 'LogDetection.wsgi.application'
ASGI_APPLICATION = 'LogDetection.asgi.application'

# Channel layers configuration
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    },
}

# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': config('DB_ENGINE', default='django.db.backends.mysql'),
        'NAME': config('DB_NAME', default='log_detection'),
        'USER': config('DB_USER', default='root'),
        'PASSWORD': config('DB_PASSWORD', default=''),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='3306'),
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 4,  # Set to a lower value for simpler passwords
        }
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

STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'frontend', 'static'),
]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGIN_REDIRECT_URL = '/'  # Redirect to homepage after login
LOGOUT_REDIRECT_URL = '/login/'  # Redirect to login page after logout
SIGNUP_REDIRECT_URL = '/login/'  # Redirect to login page after signup

# Update the login redirect settings
LOGIN_URL = '/login/'  # URL where users should be redirected for login

# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_USE_SSL = config('EMAIL_USE_SSL', default=False, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD') 
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='Log Analyzer <noreply.loganalyzer@gmail.com>')

# Threat Intelligence API keys
ABUSEIPDB_API_KEY = config('ABUSEIPDB_API_KEY', default='')
VIRUSTOTAL_API_KEY = config('VIRUSTOTAL_API_KEY', default='')

# Mock data for testing without API keys
USE_MOCK_THREAT_INTELLIGENCE = config('USE_MOCK_THREAT_INTELLIGENCE', default=True, cast=bool)

# OpenRouter API Configuration
OPENROUTER_API_KEY = config('OPENROUTER_API_KEY')
OPENROUTER_MODEL = config('OPENROUTER_MODEL', default='openai/gpt-4o-mini')
OPENAI_MAX_TOKENS = config('OPENAI_MAX_TOKENS', default=1000, cast=int)
OPENAI_TEMPERATURE = config('OPENAI_TEMPERATURE', default=0.2, cast=float)

# AI Report Configuration
AI_REPORT_CACHE_HOURS = config('AI_REPORT_CACHE_HOURS', default=24, cast=int)

# Site Configuration
SITE_NAME = config('SITE_NAME', default='Log Detection Platform')

OPENAI_API_KEY = config('OPENAI_API_KEY', default='placeholder')

# Password hashers
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]

ENABLE_REALTIME_LOG_PROCESSING = config('ENABLE_REALTIME_LOG_PROCESSING', default=True, cast=bool)

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'django_debug.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        '': {  # Root logger
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True,
        },
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'log_ingestion': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'threat_detection': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'authentication': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}

# Kafka Configuration
AUTO_START_KAFKA = config('AUTO_START_KAFKA', default=True, cast=bool)
KAFKA_HOME = config('KAFKA_HOME', default=r"C:\Kafka_2.13-3.8.1")
KAFKA_BOOTSTRAP_SERVERS = config('KAFKA_BOOTSTRAP_SERVERS', default='localhost:9092', cast=Csv())
KAFKA_RAW_LOGS_TOPIC = config('KAFKA_RAW_LOGS_TOPIC', default='raw_logs')
KAFKA_APACHE_LOGS_TOPIC = config('KAFKA_APACHE_LOGS_TOPIC', default='apache_logs')
KAFKA_MYSQL_LOGS_TOPIC = config('KAFKA_MYSQL_LOGS_TOPIC', default='mysql_logs')
KAFKA_CONSUMER_GROUP = config('KAFKA_CONSUMER_GROUP', default='log_parser_group')

# Required API Keys for notifications
FCM_API_KEY = config('FCM_API_KEY', default='')
SITE_URL = config('SITE_URL', default='http://localhost:8000')

# Add to LogDetection/settings.py for development only
CELERY_TASK_ALWAYS_EAGER = True  # Run tasks synchronously

AUTHENTICATION_BACKENDS = [
    'authentication.views.EmailOrUsernameModelBackend',  # Our custom backend
    'django.contrib.auth.backends.ModelBackend',  # Default Django backend
]

