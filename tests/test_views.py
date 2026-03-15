import pytest
import pyotp
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from django_admin_2fa.models import BackupCode, TOTPDevice, TwoFALoginAttempt
from django_admin_2fa.utils import encrypt_secret, generate_secret

User = get_user_model()


@pytest.fixture
def client():
    return Client()


@pytest.fixture
def staff_user(db):
    return User.objects.create_user(
        username="viewstaff",
        password="testpass123",
        email="viewstaff@example.com",
        is_staff=True,
    )


@pytest.fixture
def setup_device(staff_user):
    """Create a verified TOTP device and return (user, raw_secret)."""
    secret = generate_secret()
    TOTPDevice.objects.create(
        user=staff_user,
        secret=encrypt_secret(secret),
        is_verified=True,
    )
    return staff_user, secret


def login_and_verify(client, staff_user):
    """Login and mark session as 2FA verified."""
    client.login(username=staff_user.get_username(), password="testpass123")
    session = client.session
    session["admin_2fa_verified"] = True
    session.save()


class TestVerifyView:
    def test_get_renders(self, client, setup_device):
        user, _ = setup_device
        client.login(username="viewstaff", password="testpass123")
        response = client.get(reverse("admin_2fa:verify"))
        assert response.status_code == 200
        assert "viewstaff" in response.content.decode()

    def test_valid_totp_redirects(self, client, setup_device):
        user, secret = setup_device
        client.login(username="viewstaff", password="testpass123")
        token = pyotp.TOTP(secret).now()
        response = client.post(reverse("admin_2fa:verify"), {"code": token, "use_backup": "0"})
        assert response.status_code == 302
        assert client.session.get("admin_2fa_verified") is True

    def test_invalid_totp_shows_error(self, client, setup_device):
        user, _ = setup_device
        client.login(username="viewstaff", password="testpass123")
        response = client.post(reverse("admin_2fa:verify"), {"code": "000000", "use_backup": "0"})
        assert response.status_code == 200
        assert "Geçersiz" in response.content.decode()

    def test_valid_backup_code(self, client, setup_device):
        user, _ = setup_device
        client.login(username="viewstaff", password="testpass123")
        codes = BackupCode.generate_codes(user)
        response = client.post(
            reverse("admin_2fa:verify"),
            {"code": codes[0], "use_backup": "1"},
        )
        assert response.status_code == 302
        assert client.session.get("admin_2fa_verified") is True

    def test_lockout_after_max_attempts(self, client, setup_device):
        user, _ = setup_device
        client.login(username="viewstaff", password="testpass123")
        for _ in range(5):
            TwoFALoginAttempt.objects.create(
                user=user, ip_address="127.0.0.1", success=False, method="totp"
            )
        response = client.post(
            reverse("admin_2fa:verify"), {"code": "000000", "use_backup": "0"}
        )
        assert response.status_code == 200
        assert "Kilitlendi" in response.content.decode()


class TestSetupView:
    def test_get_renders_qr(self, client, staff_user):
        client.login(username="viewstaff", password="testpass123")
        response = client.get(reverse("admin_2fa:setup"))
        assert response.status_code == 200
        assert "data:image/png;base64" in response.content.decode()

    def test_redirects_if_device_exists(self, client, setup_device):
        user, _ = setup_device
        client.login(username="viewstaff", password="testpass123")
        response = client.get(reverse("admin_2fa:setup"))
        assert response.status_code == 302
        assert "manage" in response.url

    def test_valid_code_creates_device(self, client, staff_user):
        client.login(username="viewstaff", password="testpass123")
        # First GET to set session secret
        client.get(reverse("admin_2fa:setup"))
        secret = client.session["_2fa_setup_secret"]
        token = pyotp.TOTP(secret).now()
        response = client.post(reverse("admin_2fa:setup"), {"code": token})
        assert response.status_code == 302
        assert TOTPDevice.objects.filter(user=staff_user, is_verified=True).exists()

    def test_invalid_code_shows_error(self, client, staff_user):
        client.login(username="viewstaff", password="testpass123")
        client.get(reverse("admin_2fa:setup"))
        response = client.post(reverse("admin_2fa:setup"), {"code": "000000"})
        assert response.status_code == 200
        assert "Geçersiz" in response.content.decode()


class TestBackupCodesView:
    def test_get_shows_stats(self, client, setup_device):
        user, _ = setup_device
        login_and_verify(client, user)
        BackupCode.generate_codes(user)
        response = client.get(reverse("admin_2fa:backup-codes"))
        assert response.status_code == 200
        assert "10" in response.content.decode()

    def test_post_regenerates_codes(self, client, setup_device):
        user, _ = setup_device
        login_and_verify(client, user)
        BackupCode.generate_codes(user)
        response = client.post(reverse("admin_2fa:backup-codes"))
        assert response.status_code == 302
        assert BackupCode.objects.filter(user=user, is_used=False).count() == 10


class TestManageView:
    def test_get_shows_status(self, client, setup_device):
        user, _ = setup_device
        login_and_verify(client, user)
        response = client.get(reverse("admin_2fa:manage"))
        assert response.status_code == 200
        assert "Aktif" in response.content.decode()

    def test_reset_deletes_device(self, client, setup_device):
        user, _ = setup_device
        login_and_verify(client, user)
        response = client.post(
            reverse("admin_2fa:manage"), {"action": "reset"}
        )
        assert response.status_code == 302
        assert not TOTPDevice.objects.filter(user=user).exists()


class TestNotMyAccountView:
    def test_logout_redirects(self, client, setup_device):
        user, _ = setup_device
        client.login(username="viewstaff", password="testpass123")
        response = client.post(reverse("admin_2fa:logout"))
        assert response.status_code == 302
        assert "login" in response.url
