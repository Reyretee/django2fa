# django-admin-2fa

TOTP-based two-factor authentication for Django admin. Works with Google Authenticator, Authy, 1Password, and any TOTP-compatible app.

## Features

- TOTP authentication with QR code setup
- Backup codes (10 per user, single-use)
- Brute force protection (account lockout after failed attempts)
- Middleware-based — no changes to Django's auth system
- Works with any admin theme (Unfold, Grappelli, Jazzmin, etc.)
- Encrypted secret storage using `django.core.signing`
- Hashed backup codes using Django's password hashing

## Installation

```bash
pip install django-admin-totp
```

## Quick Start

**1. Add to `INSTALLED_APPS` (before `django.contrib.admin`):**

```python
INSTALLED_APPS = [
    'django_admin_2fa',
    'django.contrib.admin',
    ...
]
```

**2. Add middleware:**

```python
MIDDLEWARE = [
    ...
    'django_admin_2fa.middleware.TwoFactorMiddleware',
]
```

**3. Add URLs (before admin URLs):**

```python
from django.urls import include, path

urlpatterns = [
    path('admin/2fa/', include('django_admin_2fa.urls')),
    path('admin/', admin.site.urls),
]
```

**4. Run migrations:**

```bash
python manage.py migrate django_admin_2fa
```

That's it. Staff users will be redirected to 2FA setup on their next login.

## Configuration

All settings are optional. Add to `settings.py`:

```python
ADMIN_2FA = {
    'TOTP_ISSUER': 'My App',        # Name shown in authenticator app
    'BACKUP_CODE_COUNT': 10,         # Number of backup codes per user
    'MAX_ATTEMPTS': 5,               # Failed attempts before lockout
    'LOCKOUT_DURATION': 900,         # Lockout duration in seconds (default: 15 min)
    'REQUIRE_2FA_FOR_STAFF': True,   # Require 2FA for all staff users
}
```

## User Flow

1. Staff user logs in with username + password
2. Redirected to 2FA setup (first time) or verification screen
3. Scans QR code with authenticator app
4. Enters 6-digit code to verify
5. Receives 10 single-use backup codes
6. On subsequent logins, enters TOTP code to access admin

## Admin Panel

The following models are available in the Django admin:

- **TOTP Devices** — View and manage user devices
- **Backup Codes** — View backup code usage
- **2FA Login Attempts** — Monitor login attempts, unlock users

## Pages

| URL | Description |
|---|---|
| `/admin/2fa/verify/` | Enter TOTP or backup code |
| `/admin/2fa/setup/` | QR code setup for new devices |
| `/admin/2fa/backup-codes/` | View and regenerate backup codes |
| `/admin/2fa/manage/` | 2FA status, reset device |

## Requirements

- Python >= 3.10
- Django >= 4.2
- pyotp >= 2.9.0
- qrcode >= 7.4

## License

MIT
