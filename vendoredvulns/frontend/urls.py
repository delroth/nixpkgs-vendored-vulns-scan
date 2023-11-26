from django.contrib import admin
from django.urls import path, include
from django.conf import settings

from . import views

api_patterns = [
    path("scan/result", views.ApiPostScanResult.as_view(), name="api-post-scan-result"),
]

urlpatterns = [
    path("api/v1/", include(api_patterns)),
    path("accounts/", include("allauth.urls")),
    path("admin/", admin.site.urls),
    path("", views.Home.as_view()),
]

if "debug_toolbar" in settings.INSTALLED_APPS:
    urlpatterns.append(path("__debug__/", include("debug_toolbar.urls")))
