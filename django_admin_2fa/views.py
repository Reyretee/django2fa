from django.contrib import messages
from django.contrib.auth import logout
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views import View

import pyotp

from .conf import get_setting
from .decorators import staff_required, twofa_verified_required
from .models import BackupCode, TOTPDevice, TwoFALoginAttempt
from .utils import generate_qr_code, generate_secret, get_client_ip


@method_decorator(staff_required, name="dispatch")
class TwoFAVerifyView(View):
    template_name = "admin_2fa/verify.html"

    def get(self, request):
        context = self._get_context(request)
        return render(request, self.template_name, context)

    def post(self, request):
        user = request.user
        context = self._get_context(request)

        if TwoFALoginAttempt.is_locked_out(user):
            remaining = TwoFALoginAttempt.get_lockout_remaining(user)
            context["error"] = f"Hesabınız geçici olarak kilitlendi. {remaining} saniye sonra tekrar deneyin."
            context["is_locked_out"] = True
            context["lockout_remaining"] = remaining
            return render(request, self.template_name, context)

        code = request.POST.get("code", "").strip()
        use_backup = request.POST.get("use_backup") == "1"
        ip = get_client_ip(request)

        if use_backup:
            success = self._verify_backup_code(user, code, ip)
        else:
            success = self._verify_totp(user, code, ip)

        if success:
            request.session["admin_2fa_verified"] = True
            next_url = request.GET.get("next") or request.POST.get("next") or reverse("admin:index")
            return redirect(next_url)

        context["error"] = "Geçersiz kod. Lütfen tekrar deneyin."
        context["has_error"] = True
        return render(request, self.template_name, context)

    def _verify_totp(self, user, code, ip):
        try:
            device = user.totp_device
        except TOTPDevice.DoesNotExist:
            return False

        success = device.verify_token(code)
        TwoFALoginAttempt.objects.create(
            user=user, ip_address=ip, success=success, method="totp"
        )
        return success

    def _verify_backup_code(self, user, code, ip):
        unused_codes = BackupCode.objects.filter(user=user, is_used=False)
        for backup_code in unused_codes:
            if backup_code.verify(code):
                TwoFALoginAttempt.objects.create(
                    user=user, ip_address=ip, success=True, method="backup"
                )
                return True

        TwoFALoginAttempt.objects.create(
            user=user, ip_address=ip, success=False, method="backup"
        )
        return False

    def _get_context(self, request):
        user = request.user
        is_locked = TwoFALoginAttempt.is_locked_out(user)
        return {
            "username": user.get_username(),
            "is_locked_out": is_locked,
            "lockout_remaining": TwoFALoginAttempt.get_lockout_remaining(user) if is_locked else 0,
            "next_url": request.GET.get("next", ""),
            "error": None,
            "has_error": False,
            "title": "İki Faktörlü Doğrulama",
        }


@method_decorator(staff_required, name="dispatch")
class TwoFASetupView(View):
    template_name = "admin_2fa/setup.html"

    def get(self, request):
        if hasattr(request.user, "totp_device") and request.user.totp_device.is_verified:
            return redirect(reverse("admin_2fa:manage"))

        secret = request.session.get("_2fa_setup_secret")
        if not secret:
            secret = generate_secret()
            request.session["_2fa_setup_secret"] = secret

        totp = pyotp.TOTP(secret)
        email = getattr(request.user, "email", str(request.user))
        provisioning_uri = totp.provisioning_uri(
            name=email,
            issuer_name=get_setting("TOTP_ISSUER"),
        )
        qr_data_uri = generate_qr_code(provisioning_uri)

        context = {
            "qr_code": qr_data_uri,
            "secret_key": secret,
            "error": None,
            "title": "2FA Kurulumu",
        }
        return render(request, self.template_name, context)

    def post(self, request):
        secret = request.session.get("_2fa_setup_secret")
        if not secret:
            return redirect(reverse("admin_2fa:setup"))

        code = request.POST.get("code", "").strip()
        totp = pyotp.TOTP(secret)

        if totp.verify(code, valid_window=5):
            device, created = TOTPDevice.objects.get_or_create(user=request.user)
            device.set_secret(secret)
            device.is_verified = True
            device.save()

            del request.session["_2fa_setup_secret"]

            plaintext_codes = BackupCode.generate_codes(request.user)
            request.session["_2fa_backup_codes"] = plaintext_codes
            request.session["admin_2fa_verified"] = True

            return redirect(reverse("admin_2fa:backup-codes"))

        totp_obj = pyotp.TOTP(secret)
        email = getattr(request.user, "email", str(request.user))
        provisioning_uri = totp_obj.provisioning_uri(
            name=email,
            issuer_name=get_setting("TOTP_ISSUER"),
        )
        qr_data_uri = generate_qr_code(provisioning_uri)

        context = {
            "qr_code": qr_data_uri,
            "secret_key": secret,
            "error": "Geçersiz kod. Lütfen tekrar deneyin.",
            "title": "2FA Kurulumu",
        }
        return render(request, self.template_name, context)


@method_decorator(twofa_verified_required, name="dispatch")
class TwoFABackupCodesView(View):
    template_name = "admin_2fa/backup_codes.html"

    def get(self, request):
        codes = request.session.pop("_2fa_backup_codes", None)
        total = get_setting("BACKUP_CODE_COUNT")
        used = BackupCode.objects.filter(user=request.user, is_used=True).count()
        remaining = BackupCode.objects.filter(user=request.user, is_used=False).count()

        context = {
            "codes": codes,
            "total": total,
            "used": used,
            "remaining": remaining,
            "show_codes": codes is not None,
            "title": "Yedek Kodlar",
        }
        return render(request, self.template_name, context)

    def post(self, request):
        plaintext_codes = BackupCode.generate_codes(request.user)
        request.session["_2fa_backup_codes"] = plaintext_codes
        messages.success(request, "Yeni yedek kodlar oluşturuldu.")
        return redirect(reverse("admin_2fa:backup-codes"))


@method_decorator(twofa_verified_required, name="dispatch")
class TwoFAManageView(View):
    template_name = "admin_2fa/manage.html"

    def get(self, request):
        device = getattr(request.user, "totp_device", None)
        has_device = device is not None and device.is_verified if device else False

        last_attempt = TwoFALoginAttempt.objects.filter(
            user=request.user, success=True
        ).first()

        remaining_codes = BackupCode.objects.filter(
            user=request.user, is_used=False
        ).count()

        context = {
            "has_device": has_device,
            "device": device,
            "last_attempt": last_attempt,
            "remaining_codes": remaining_codes,
            "title": "2FA Yönetimi",
        }
        return render(request, self.template_name, context)

    def post(self, request):
        action = request.POST.get("action")
        if action == "reset":
            TOTPDevice.objects.filter(user=request.user).delete()
            BackupCode.objects.filter(user=request.user).delete()
            request.session.pop("admin_2fa_verified", None)
            messages.success(request, "2FA sıfırlandı. Yeniden kurulum yapmanız gerekiyor.")
            return redirect(reverse("admin_2fa:setup"))
        return redirect(reverse("admin_2fa:manage"))


@method_decorator(staff_required, name="dispatch")
class NotMyAccountView(View):
    def post(self, request):
        logout(request)
        messages.info(request, "Oturum kapatıldı. Farklı bir hesapla giriş yapabilirsiniz.")
        return redirect(reverse("admin:login"))
