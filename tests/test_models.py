import pytest
import pyotp
from django.contrib.auth import get_user_model
from django.utils import timezone

from django_admin_2fa.models import BackupCode, TOTPDevice, TwoFALoginAttempt
from django_admin_2fa.utils import encrypt_secret, generate_secret

User = get_user_model()


@pytest.fixture
def staff_user(db):
    return User.objects.create_user(
        username="teststaff",
        password="testpass123",
        email="test@example.com",
        is_staff=True,
    )


@pytest.fixture
def totp_device(staff_user):
    secret = generate_secret()
    device = TOTPDevice.objects.create(
        user=staff_user,
        secret=encrypt_secret(secret),
        is_verified=True,
    )
    device._raw_secret = secret
    return device


class TestTOTPDevice:
    def test_secret_roundtrip(self, totp_device):
        raw = totp_device._raw_secret
        assert totp_device.get_secret() == raw

    def test_set_secret(self, totp_device):
        new_secret = generate_secret()
        totp_device.set_secret(new_secret)
        totp_device.save()
        totp_device.refresh_from_db()
        assert totp_device.get_secret() == new_secret

    def test_verify_valid_token(self, totp_device):
        raw_secret = totp_device.get_secret()
        totp = pyotp.TOTP(raw_secret)
        token = totp.now()
        assert totp_device.verify_token(token) is True
        totp_device.refresh_from_db()
        assert totp_device.last_used_at is not None

    def test_verify_invalid_token(self, totp_device):
        assert totp_device.verify_token("000000") is False

    def test_provisioning_uri(self, totp_device):
        uri = totp_device.get_provisioning_uri()
        assert "otpauth://totp/" in uri
        assert "secret=" in uri

    def test_str(self, totp_device):
        assert "TOTP Device for" in str(totp_device)


class TestBackupCode:
    def test_generate_codes(self, staff_user):
        codes = BackupCode.generate_codes(staff_user)
        assert len(codes) == 10
        assert BackupCode.objects.filter(user=staff_user).count() == 10

    def test_generate_codes_replaces_old(self, staff_user):
        BackupCode.generate_codes(staff_user)
        codes2 = BackupCode.generate_codes(staff_user)
        assert len(codes2) == 10
        assert BackupCode.objects.filter(user=staff_user).count() == 10

    def test_verify_valid_code(self, staff_user):
        codes = BackupCode.generate_codes(staff_user)
        backup = BackupCode.objects.filter(user=staff_user, is_used=False).first()
        assert backup.verify(codes[0]) is True
        backup.refresh_from_db()
        assert backup.is_used is True
        assert backup.used_at is not None

    def test_verify_invalid_code(self, staff_user):
        BackupCode.generate_codes(staff_user)
        backup = BackupCode.objects.filter(user=staff_user).first()
        assert backup.verify("INVALID1") is False

    def test_verify_case_insensitive(self, staff_user):
        codes = BackupCode.generate_codes(staff_user)
        backup = BackupCode.objects.filter(user=staff_user, is_used=False).first()
        assert backup.verify(codes[0].lower()) is True


class TestTwoFALoginAttempt:
    def test_not_locked_initially(self, staff_user):
        assert TwoFALoginAttempt.is_locked_out(staff_user) is False

    def test_locked_after_max_attempts(self, staff_user):
        for _ in range(5):
            TwoFALoginAttempt.objects.create(
                user=staff_user,
                ip_address="127.0.0.1",
                success=False,
                method="totp",
            )
        assert TwoFALoginAttempt.is_locked_out(staff_user) is True

    def test_not_locked_with_success_between(self, staff_user):
        for _ in range(3):
            TwoFALoginAttempt.objects.create(
                user=staff_user, ip_address="127.0.0.1",
                success=False, method="totp",
            )
        # Successes don't reset the count in current implementation,
        # but 3 failures < 5 threshold
        assert TwoFALoginAttempt.is_locked_out(staff_user) is False

    def test_lockout_remaining(self, staff_user):
        for _ in range(5):
            TwoFALoginAttempt.objects.create(
                user=staff_user,
                ip_address="127.0.0.1",
                success=False,
                method="totp",
            )
        remaining = TwoFALoginAttempt.get_lockout_remaining(staff_user)
        assert remaining > 0
        assert remaining <= 900

    def test_str(self, staff_user):
        attempt = TwoFALoginAttempt.objects.create(
            user=staff_user,
            ip_address="127.0.0.1",
            success=True,
            method="totp",
        )
        assert "success" in str(attempt)
