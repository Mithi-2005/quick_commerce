from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("qc_app.urls")),
    path("merchants/", include("merchants.urls")),
]
