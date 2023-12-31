"""
Django settings for vendoredvulns.frontend project.

Generated by 'django-admin startproject' using Django 4.2.7.

https://docs.djangoproject.com/en/4.2/topics/settings/
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.urandom(32)

DEBUG = True

ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

if hosts := os.environ.get("ALLOWED_HOSTS"):
    ALLOWED_HOSTS += hosts.split(",")

GITHUB_API_TOKEN = ""
GITHUB_EXTRA_USERS = set()
GITHUB_DENYLISTED_USERS = set()

# The token in "Authorization: Token <token>" for API endpoints.
API_SECRET_TOKEN = "changeme"

INTERNAL_IPS = ["127.0.0.1"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "simple_history",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.github",
    "rest_framework",
    "vendoredvulns.frontend",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
    "simple_history.middleware.HistoryRequestMiddleware",
]

AUTHENTICATION_BACKENDS = [
    # Local users: superusers, etc.
    "django.contrib.auth.backends.ModelBackend",
    # GitHub OAuth. The GitHub app config must be added in the Django admin.
    "allauth.account.auth_backends.AuthenticationBackend",
]

# Forbid local allauth account creation.
ACCOUNT_ADAPTER = "vendoredvulns.frontend.auth.NoSignupAccountAdapter"
SOCIALACCOUNT_ADAPTER = (
    "vendoredvulns.frontend.auth.GithubNixosTeamSocialAccountAdapter"
)
SOCIALACCOUNT_PROVIDERS = {
    "github": {
        "EMAIL_AUTHENTICATION": False,
        "EMAIL_AUTHENTICATION_AUTO_CONNECT": False,
        "EMAIL_REQUIRED": False,
        "SCOPE": [
            "read:user",
            # "user:email",
        ],
    }
}

ROOT_URLCONF = "vendoredvulns.frontend.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "vendoredvulns.frontend.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": (
            "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"
        ),
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
