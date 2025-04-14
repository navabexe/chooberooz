TEMPLATE_KEYS = [
    "login_success",
    "otp_requested",
    "otp_verified",
    "account_deleted",
    "user.profile_completed",
    "admin.user_joined",
    "vendor.profile_pending",
    "admin.vendor_submitted",
    "vendor.active",
    "admin.vendor_pending",
    "admin_alert_login_failure",
    "notification_failed"
]

TEMPLATE_VARIABLES = {
    "login_success": ["user_id", "time"],
    "otp_requested": ["phone", "otp", "purpose"],
    "otp_verified": ["phone", "role"],
    "account_deleted": ["user_id"],
    "user.profile_completed": ["name", "phone"],
    "admin.user_joined": ["user_name", "user_phone"],
    "vendor.profile_pending": ["name", "phone"],
    "admin.vendor_submitted": ["vendor_name", "vendor_phone"],
    "vendor.active": ["phone"],
    "admin.vendor_pending": ["name"],
    "admin_alert_login_failure": ["user_id", "ip"],
    "notification_failed": ["receiver_id", "error", "type"]
}