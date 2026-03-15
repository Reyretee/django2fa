from functools import wraps

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.urls import reverse


def staff_required(view_func):
    @wraps(view_func)
    @login_required(login_url="admin:login")
    def wrapper(request, *args, **kwargs):
        if not request.user.is_staff:
            return HttpResponseForbidden("Staff access required.")
        return view_func(request, *args, **kwargs)
    return wrapper


def twofa_verified_required(view_func):
    @wraps(view_func)
    @staff_required
    def wrapper(request, *args, **kwargs):
        if not request.session.get("admin_2fa_verified"):
            return redirect(reverse("admin_2fa:verify"))
        return view_func(request, *args, **kwargs)
    return wrapper
