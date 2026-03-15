from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/2fa/", include("django_admin_2fa.urls")),
    path("admin/", admin.site.urls),
]
