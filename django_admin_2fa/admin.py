from django.contrib import admin

from .models import BackupCode, TOTPDevice, TwoFALoginAttempt


@admin.register(TOTPDevice)
class TOTPDeviceAdmin(admin.ModelAdmin):
    list_display = ["user", "is_verified", "created_at", "last_used_at"]
    list_filter = ["is_verified"]
    search_fields = ["user__username", "user__email"]
    readonly_fields = ["secret", "created_at", "last_used_at"]

    def has_add_permission(self, request):
        return False


@admin.register(BackupCode)
class BackupCodeAdmin(admin.ModelAdmin):
    list_display = ["user", "is_used", "used_at", "created_at"]
    list_filter = ["is_used"]
    search_fields = ["user__username"]
    readonly_fields = ["code_hash", "is_used", "used_at", "created_at"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(TwoFALoginAttempt)
class TwoFALoginAttemptAdmin(admin.ModelAdmin):
    list_display = ["user", "ip_address", "success", "method", "timestamp"]
    list_filter = ["success", "method"]
    search_fields = ["user__username", "ip_address"]
    readonly_fields = ["user", "ip_address", "success", "method", "timestamp"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    actions = ["unlock_users"]

    @admin.action(description="Unlock selected users (clear failed attempts)")
    def unlock_users(self, request, queryset):
        users = set(queryset.values_list("user", flat=True))
        deleted, _ = TwoFALoginAttempt.objects.filter(
            user__in=users, success=False
        ).delete()
        self.message_user(
            request,
            f"{deleted} failed attempt(s) cleared for {len(users)} user(s).",
        )
