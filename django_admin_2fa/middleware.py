from django.shortcuts import redirect
from django.template.response import SimpleTemplateResponse
from django.urls import reverse

from .models import TOTPDevice
from .conf import get_setting

TWOFA_WIDGET = (
    '<div id="twofa-fab" style="'
    "position:fixed;bottom:24px;right:24px;z-index:99999;"
    "background:#e67e22;color:#fff;"
    "width:48px;height:48px;border-radius:50%;"
    "display:flex;align-items:center;justify-content:center;"
    "cursor:pointer;box-shadow:0 2px 12px rgba(0,0,0,.25);"
    "font-weight:700;font-size:14px;font-family:sans-serif;"
    "text-decoration:none;transition:transform .15s,box-shadow .15s;"
    '" '
    "onmouseenter=\"this.style.transform='scale(1.1)'\" "
    "onmouseleave=\"this.style.transform='scale(1)'\" "
    'onclick="window.location.href=\'{url}\'" title="2FA Ayarları">'
    '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" '
    'stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>'
    '<path d="M7 11V7a5 5 0 0 1 10 0v4"/>'
    "</svg></div>"
)


class TwoFactorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return self.get_response(request)

        if not request.user.is_staff:
            return self.get_response(request)

        if self._is_whitelisted(request):
            return self.get_response(request)

        try:
            device = request.user.totp_device
            has_verified_device = device.is_verified
        except TOTPDevice.DoesNotExist:
            has_verified_device = False

        if has_verified_device and request.session.get("admin_2fa_verified"):
            response = self.get_response(request)
            if self._is_admin_path(request):
                self._inject_widget(response)
            return response

        is_admin = self._is_admin_path(request)
        is_post_login_redirect = self._is_post_login_redirect(request)

        if not is_admin and not is_post_login_redirect:
            return self.get_response(request)

        if not has_verified_device:
            if not get_setting("REQUIRE_2FA_FOR_STAFF"):
                return self.get_response(request)
            return redirect(reverse("admin_2fa:setup"))

        verify_url = reverse("admin_2fa:verify")
        next_url = reverse("admin:index")
        return redirect(f"{verify_url}?next={next_url}")

    def _inject_widget(self, response):
        try:
            manage_url = reverse("admin_2fa:manage")
        except Exception:
            return

        # Handle TemplateResponse (used by Django admin)
        if isinstance(response, SimpleTemplateResponse):
            if not response.is_rendered:
                response.add_post_render_callback(
                    lambda r: self._do_inject(r, manage_url)
                )
                return
        self._do_inject(response, manage_url)

    @staticmethod
    def _do_inject(response, manage_url):
        content_type = response.get("Content-Type", "")
        if "text/html" not in content_type:
            return
        if not hasattr(response, "content"):
            return
        content = response.content.decode("utf-8")
        if "</body>" not in content:
            return
        widget = TWOFA_WIDGET.format(url=manage_url)
        response.content = content.replace("</body>", widget + "</body>").encode("utf-8")
        response["Content-Length"] = len(response.content)

    def _is_admin_path(self, request):
        try:
            admin_prefix = reverse("admin:index")
        except Exception:
            admin_prefix = "/admin/"
        return request.path.startswith(admin_prefix)

    def _is_post_login_redirect(self, request):
        post_login_paths = ["/accounts/profile/", "/accounts/profile"]
        return request.path in post_login_paths

    def _is_whitelisted(self, request):
        path = request.path

        try:
            twofa_prefix = reverse("admin_2fa:verify").rsplit("verify/", 1)[0]
            if path.startswith(twofa_prefix):
                return True
        except Exception:
            pass

        try:
            if path == reverse("admin:login") or path == reverse("admin:logout"):
                return True
        except Exception:
            pass

        try:
            if path == reverse("admin:jsi18n"):
                return True
        except Exception:
            pass

        return False
