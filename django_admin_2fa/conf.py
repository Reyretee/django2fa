from django.conf import settings

DEFAULTS = {
    "TOTP_ISSUER": "Django Admin",
    "BACKUP_CODE_COUNT": 10,
    "MAX_ATTEMPTS": 5,
    "LOCKOUT_DURATION": 900,
    "REQUIRE_2FA_FOR_STAFF": True,
}


def get_setting(key):
    user_settings = getattr(settings, "ADMIN_2FA", {})
    return user_settings.get(key, DEFAULTS[key])
