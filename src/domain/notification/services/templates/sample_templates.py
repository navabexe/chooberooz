TEMPLATE_KEYS = [
    "login_success",
    "otp_requested",
    "otp_verified",
    "account_deleted",
    "profile_completed",
    "admin_alert_login_failure",
    "notification_failed"
]

TEMPLATE_VARIABLES = {
    "login_success": {"user_id": "str", "time": "str"},
    "otp_requested": {"phone": "str", "otp": "str", "purpose": "str"},
    "otp_verified": {"phone": "str", "role": "str"},
    "account_deleted": {"user_id": "str"},
    "profile_completed": {"user_id": "str", "role": "str"},
    "admin_alert_login_failure": {"user_id": "str", "ip": "str"},
    "notification_failed": {"receiver_id": "str", "error": "str", "type": "str"}
}