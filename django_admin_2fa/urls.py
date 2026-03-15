from django.urls import path

from . import views

app_name = "admin_2fa"

urlpatterns = [
    path("verify/", views.TwoFAVerifyView.as_view(), name="verify"),
    path("setup/", views.TwoFASetupView.as_view(), name="setup"),
    path("backup-codes/", views.TwoFABackupCodesView.as_view(), name="backup-codes"),
    path("manage/", views.TwoFAManageView.as_view(), name="manage"),
    path("logout/", views.NotMyAccountView.as_view(), name="logout"),
]
