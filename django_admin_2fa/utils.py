import base64
import io
import secrets
import string

import pyotp
import qrcode
from django.core import signing

SALT = "totp-device-secret"


def generate_secret():
    return pyotp.random_base32()


def encrypt_secret(raw_secret):
    return signing.dumps(raw_secret, salt=SALT)


def decrypt_secret(encrypted):
    return signing.loads(encrypted, salt=SALT)


def generate_backup_code():
    chars = string.ascii_uppercase + string.digits
    part1 = "".join(secrets.choice(chars) for _ in range(4))
    part2 = "".join(secrets.choice(chars) for _ in range(4))
    return f"{part1}-{part2}"


def generate_qr_code(provisioning_uri):
    img = qrcode.make(provisioning_uri, box_size=6, border=4)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    encoded = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{encoded}"


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "0.0.0.0")
