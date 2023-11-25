from .base import *

SECRET_KEY = "test"

INSTALLED_APPS += ("debug_toolbar",)

MIDDLEWARE += ("debug_toolbar.middleware.DebugToolbarMiddleware",)
