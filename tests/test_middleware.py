import pytest
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from django_admin_2fa.models import TOTPDevice
from django_admin_2fa.utils import encrypt_secret, generate_secret

User = get_user_model()


@pytest.fixture
def client():
    return Client()


@pytest.fixture
def staff_user(db):
    return User.objects.create_user(
        username="staffuser",
        password="testpass123",
        email="staff@example.com",
        is_staff=True,
    )


@pytest.fixture
def staff_user_with_device(staff_user):
    secret = generate_secret()
    TOTPDevice.objects.create(
        user=staff_user,
        secret=encrypt_secret(secret),
        is_verified=True,
    )
    return staff_user


class TestTwoFactorMiddleware:
    def test_unauthenticated_passes_through(self, client):
        response = client.get(reverse("admin:index"))
        # Should redirect to login, not to 2FA
        assert response.status_code == 302
        assert "login" in response.url

    def test_staff_without_device_redirects_to_setup(self, client, staff_user):
        client.login(username="staffuser", password="testpass123")
        response = client.get(reverse("admin:index"))
        assert response.status_code == 302
        assert "setup" in response.url

    def test_staff_with_device_unverified_session_redirects_to_verify(
        self, client, staff_user_with_device
    ):
        client.login(username="staffuser", password="testpass123")
        response = client.get(reverse("admin:index"))
        assert response.status_code == 302
        assert "verify" in response.url

    def test_staff_with_verified_session_passes_through(
        self, client, staff_user_with_device
    ):
        client.login(username="staffuser", password="testpass123")
        session = client.session
        session["admin_2fa_verified"] = True
        session.save()
        response = client.get(reverse("admin:index"))
        assert response.status_code == 200

    def test_twofa_urls_are_whitelisted(self, client, staff_user):
        client.login(username="staffuser", password="testpass123")
        response = client.get(reverse("admin_2fa:setup"))
        assert response.status_code == 200

    def test_non_admin_paths_pass_through(self, client):
        # Non-admin paths should not be intercepted
        response = client.get("/nonexistent/")
        assert response.status_code == 404

    @override_settings(ADMIN_2FA={"REQUIRE_2FA_FOR_STAFF": False})
    def test_optional_2fa_passes_without_device(self, client, staff_user):
        client.login(username="staffuser", password="testpass123")
        response = client.get(reverse("admin:index"))
        assert response.status_code == 200
