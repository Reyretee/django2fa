import re

import pytest

from django_admin_2fa.utils import (
    decrypt_secret,
    encrypt_secret,
    generate_backup_code,
    generate_qr_code,
    generate_secret,
    get_client_ip,
)


class TestGenerateSecret:
    def test_returns_base32_string(self):
        secret = generate_secret()
        assert re.match(r"^[A-Z2-7]+=*$", secret)

    def test_returns_different_values(self):
        s1 = generate_secret()
        s2 = generate_secret()
        assert s1 != s2


class TestEncryptDecrypt:
    def test_roundtrip(self):
        raw = generate_secret()
        encrypted = encrypt_secret(raw)
        assert encrypted != raw
        assert decrypt_secret(encrypted) == raw


class TestGenerateBackupCode:
    def test_format(self):
        code = generate_backup_code()
        assert re.match(r"^[A-Z0-9]{4}-[A-Z0-9]{4}$", code)

    def test_uniqueness(self):
        codes = {generate_backup_code() for _ in range(50)}
        assert len(codes) > 40  # statistically should be unique


class TestGenerateQrCode:
    def test_returns_data_uri(self):
        uri = generate_qr_code("otpauth://totp/Test:user@test.com?secret=ABC123&issuer=Test")
        assert uri.startswith("data:image/png;base64,")


class TestGetClientIp:
    def test_from_remote_addr(self):
        class FakeRequest:
            META = {"REMOTE_ADDR": "192.168.1.1"}
        assert get_client_ip(FakeRequest()) == "192.168.1.1"

    def test_from_forwarded_for(self):
        class FakeRequest:
            META = {
                "HTTP_X_FORWARDED_FOR": "10.0.0.1, 192.168.1.1",
                "REMOTE_ADDR": "127.0.0.1",
            }
        assert get_client_ip(FakeRequest()) == "10.0.0.1"
