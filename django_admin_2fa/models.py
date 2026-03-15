from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from django.utils import timezone

import pyotp

from .conf import get_setting
from .utils import decrypt_secret, encrypt_secret, generate_backup_code


class TOTPDevice(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="totp_device",
    )
    secret = models.TextField()
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "TOTP Device"
        verbose_name_plural = "TOTP Devices"

    def __str__(self):
        return f"TOTP Device for {self.user}"

    def get_secret(self):
        return decrypt_secret(self.secret)

    def set_secret(self, raw_secret):
        self.secret = encrypt_secret(raw_secret)

    def verify_token(self, token):
        totp = pyotp.TOTP(self.get_secret())
        if totp.verify(token, valid_window=5):
            self.last_used_at = timezone.now()
            self.save(update_fields=["last_used_at"])
            return True
        return False

    def get_provisioning_uri(self):
        raw_secret = self.get_secret()
        totp = pyotp.TOTP(raw_secret)
        email = getattr(self.user, "email", str(self.user))
        return totp.provisioning_uri(
            name=email,
            issuer_name=get_setting("TOTP_ISSUER"),
        )


class BackupCode(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="backup_codes",
    )
    code_hash = models.CharField(max_length=128)
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Backup Code"
        verbose_name_plural = "Backup Codes"

    def __str__(self):
        status = "used" if self.is_used else "active"
        return f"Backup Code for {self.user} ({status})"

    def verify(self, raw_code):
        normalized = raw_code.upper().strip()
        if check_password(normalized, self.code_hash):
            self.is_used = True
            self.used_at = timezone.now()
            self.save(update_fields=["is_used", "used_at"])
            return True
        return False

    @classmethod
    def generate_codes(cls, user):
        cls.objects.filter(user=user).delete()
        count = get_setting("BACKUP_CODE_COUNT")
        plaintext_codes = []
        for _ in range(count):
            code = generate_backup_code()
            plaintext_codes.append(code)
            cls.objects.create(
                user=user,
                code_hash=make_password(code),
            )
        return plaintext_codes


class TwoFALoginAttempt(models.Model):
    METHOD_CHOICES = [
        ("totp", "TOTP"),
        ("backup", "Backup Code"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="two_fa_attempts",
    )
    ip_address = models.GenericIPAddressField()
    success = models.BooleanField()
    method = models.CharField(max_length=10, choices=METHOD_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        verbose_name = "2FA Login Attempt"
        verbose_name_plural = "2FA Login Attempts"

    def __str__(self):
        status = "success" if self.success else "failure"
        return f"2FA {status} for {self.user} at {self.timestamp}"

    @classmethod
    def is_locked_out(cls, user):
        max_attempts = get_setting("MAX_ATTEMPTS")
        lockout_duration = get_setting("LOCKOUT_DURATION")
        cutoff = timezone.now() - timezone.timedelta(seconds=lockout_duration)
        recent_failures = cls.objects.filter(
            user=user,
            success=False,
            timestamp__gte=cutoff,
        ).count()
        return recent_failures >= max_attempts

    @classmethod
    def get_lockout_remaining(cls, user):
        max_attempts = get_setting("MAX_ATTEMPTS")
        lockout_duration = get_setting("LOCKOUT_DURATION")
        cutoff = timezone.now() - timezone.timedelta(seconds=lockout_duration)
        recent_failures = cls.objects.filter(
            user=user,
            success=False,
            timestamp__gte=cutoff,
        ).order_by("-timestamp")

        if recent_failures.count() < max_attempts:
            return 0

        oldest_relevant = recent_failures[max_attempts - 1]
        elapsed = (timezone.now() - oldest_relevant.timestamp).total_seconds()
        remaining = lockout_duration - elapsed
        return max(0, int(remaining))
