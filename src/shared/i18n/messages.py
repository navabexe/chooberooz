from typing import Dict, Optional, Literal

MESSAGES = {
    # OTP-related messages
    "otp.invalid": {
        "fa": "کد تایید اشتباه است.",
        "en": "The OTP code is incorrect."
    },
    "otp.invalid.with_attempts": {
        "fa": "کد واردشده اشتباه است. {remaining} تلاش باقی مانده است.",
        "en": "The entered code is incorrect. {remaining} attempts left."
    },
    "otp.expired": {
        "fa": "کد تایید منقضی شده است.",
        "en": "The OTP code has expired."
    },
    "otp.sent": {
        "fa": "کد تایید برای شما ارسال شد.",
        "en": "OTP has been sent to your phone."
    },
    "otp.too_many.1min": {
        "fa": "تعداد درخواست در یک دقیقه زیاد است.",
        "en": "Too many OTP requests in 1 minute."
    },
    "otp.too_many.10min": {
        "fa": "تعداد درخواست در ۱۰ دقیقه زیاد است。",
        "en": "Too many OTP requests in 10 minutes."
    },
    "otp.too_many.attempts": {
        "fa": "به دلیل تعداد بالای درخواست، موقتاً مسدود شده‌اید.",
        "en": "You are temporarily blocked due to too many attempts."
    },
    "otp.valid": {
        "fa": "کد تایید با موفقیت تأیید شد.",
        "en": "OTP has been successfully verified."
    },
    "invalid.otp_code": {
        "fa": "کد تایید باید فقط شامل اعداد باشد.",
        "en": "OTP code must contain only digits."
    },

    # Authentication-related messages
    "auth.login.success": {
        "fa": "ورود با موفقیت انجام شد.",
        "en": "Login successful."
    },
    "auth.login.success.user": {
        "fa": "کاربر عزیز، خوش آمدید!",
        "en": "Welcome, dear user!"
    },
    "auth.login.success.vendor": {
        "fa": "فروشنده گرامی، ورود شما موفق بود!",
        "en": "Hello Vendor, you have successfully logged in!"
    },
    "auth.login.success.admin": {
        "fa": "ادمین محترم، به پنل مدیریت خوش آمدید!",
        "en": "Admin, welcome to the admin panel!"
    },
    "auth.profile.incomplete": {
        "fa": "لطفاً پروفایل خود را تکمیل کنید.",
        "en": "Please complete your profile."
    },
    "auth.profile.completed": {
        "fa": "پروفایل با موفقیت تکمیل شد.",
        "en": "Profile completed successfully."
    },
    "auth.profile.pending": {
        "fa": "پروفایل در انتظار تایید ادمین است.",
        "en": "Profile is pending admin approval."
    },
    "auth.logout.single": {
        "fa": "شما با موفقیت از این نشست خارج شدید.",
        "en": "You have been logged out from this session."
    },
    "auth.logout.all": {
        "fa": "شما از تمام نشست‌ها خارج شدید.",
        "en": "You have been logged out from all sessions."
    },
    "auth.forbidden": {
        "fa": "دسترسی غیرمجاز.",
        "en": "Access denied."
    },
    "auth.force_logout.success": {
        "fa": "کاربر با موفقیت از تمام نشست‌ها خارج شد.",
        "en": "User successfully logged out from all sessions."
    },
    "auth.force_logout.no_sessions_found": {
        "fa": "کاربری با این شناسه یافت نشد یا هیچ جلسه فعالی ندارد.",
        "en": "User not found or no active sessions exist."
    },
    "auth.login.missing_credentials": {
        "fa": "شماره تلفن یا نام کاربری لازم است.",
        "en": "Phone or username is required."
    },
    "auth.login.too_many_credentials": {
        "fa": "فقط یکی از شماره تلفن یا نام کاربری را وارد کنید.",
        "en": "Provide either phone or username, not both."
    },
    "auth.login.invalid": {
        "fa": "اطلاعات ورود نامعتبر است.",
        "en": "Invalid credentials."
    },
    "auth.login.no_password": {
        "fa": "رمز عبور برای این حساب تنظیم نشده است.",
        "en": "Password not set."
    },
    "auth.login.not_active": {
        "fa": "حساب فعال نیست.",
        "en": "Account not active."
    },
    "auth.login.too_many_attempts": {
        "fa": "تعداد تلاش‌های ورود بیش از حد است. لطفاً بعداً تلاش کنید.",
        "en": "Too many login attempts. Please try again later."
    },

    # Token-related messages
    "token.invalid": {
        "fa": "توکن نامعتبر است.",
        "en": "Invalid token."
    },
    "token.expired": {
        "fa": "توکن منقضی شده است.",
        "en": "Token has expired."
    },
    "token.too_many.attempts": {
        "fa": "به دلیل تعداد بالای تلاش‌ها، موقتاً مسدود شده‌اید.",
        "en": "You are temporarily blocked due to too many attempts."
    },
    "token.refreshed": {
        "fa": "توکن‌ها با موفقیت به‌روزرسانی شدند.",
        "en": "Tokens refreshed successfully."
    },

    # User and vendor-related messages
    "user.not_found": {
        "fa": "کاربر یافت نشد.",
        "en": "User not found."
    },
    "vendor.not_eligible": {
        "fa": "فروشنده مجاز به تکمیل پروفایل نیست.",
        "en": "Vendor is not eligible for profile completion."
    },
    "vendor.approved": {
        "fa": "پروفایل فروشنده شما تأیید شد!",
        "en": "Your vendor profile has been approved!"
    },
    "vendor.rejected": {
        "fa": "پروفایل فروشنده شما رد شد.",
        "en": "Your vendor profile was rejected."
    },
    "vendor.status_update.title": {
        "fa": "به‌روزرسانی وضعیت پروفایل",
        "en": "Profile Status Update"
    },
    "vendor.invalid_id": {
        "fa": "شناسه فروشنده نامعتبر است.",
        "en": "Invalid vendor ID format."
    },
    "vendor.not_pending": {
        "fa": "فروشنده در انتظار تأیید نیست.",
        "en": "Vendor is not pending approval."
    },
    "vendor.too_many": {
        "fa": "تعداد درخواست‌های تأیید/رد بیش از حد است.",
        "en": "Too many approve/reject requests."
    },
    "vendor.invalid_action": {
        "fa": "عملیات نامعتبر است.",
        "en": "Invalid action."
    },

    # Session-related messages
    "session.invalid": {
        "fa": "نوع سشن نامعتبر است.",
        "en": "Invalid session type."
    },
    "sessions.checked": {
        "fa": {"title": "بررسی جلسات",
               "body": "جلسات شما در {time} از IP {ip} با دستگاه {device} بررسی شد. تعداد: {count}"},
        "en": {"title": "Sessions Checked",
               "body": "Your sessions were checked at {time} from IP {ip} with device {device}. Count: {count}"}
    },
    "sessions.danger": {
        "fa": {"title": "هشدار امنیتی",
               "body": "فعالیت مشکوک برای کاربر {user_id} از IP {ip} با {count} جلسه و {ip_count} آدرس IP"},
        "en": {"title": "Security Alert",
               "body": "Suspicious activity for user {user_id} from IP {ip} with {count} sessions and {ip_count} IPs"}
    },
    "sessions.active_retrieved":{
        "fa": "جلسات فعال با موفقیت بازیابی شدند.",
        "en": "Active sessions retrieved successfully."
    },
    "sessions.all_retrieved": {
        "fa": "همه جلسات با موفقیت بازیابی شدند.",
        "en": "All sessions retrieved successfully."
    },
    "auth.logout.session_not_found": {
        "fa": "جلسه مورد نظر یافت نشد.",
        "en": "The requested session was not found."
    },

    # Notification-related messages
    "notification.otp_requested.title": {
        "fa": "درخواست کد تایید",
        "en": "OTP Requested"
    },
    "notification.otp_requested.body": {
        "fa": "کد تایید برای شماره {phone} با هدف {purpose} ارسال شد. کد: {otp}",
        "en": "OTP has been sent to {phone} for {purpose} purpose. Code: {otp}"
    },
    "notification.otp_verified.title": {
        "fa": "کد تایید تأیید شد",
        "en": "OTP Verified"
    },
    "notification.otp_verified.body": {
        "fa": "کد تایید برای شماره {phone} با موفقیت تأیید شد.",
        "en": "OTP for {phone} has been successfully verified."
    },
    "notification.user.profile_completed.title": {
        "fa": "پروفایل شما با موفقیت تکمیل شد",
        "en": "Your profile has been successfully completed"
    },
    "notification.user.profile_completed.body": {
        "fa": "از اینکه اطلاعات خود را تکمیل کردید سپاسگزاریم.",
        "en": "Thank you for completing your profile."
    },
    "notification.vendor.profile_pending.title": {
        "fa": "پروفایل در انتظار تایید",
        "en": "Vendor Profile Pending"
    },
    "notification.vendor.profile_pending.body": {
        "fa": "پروفایل فروشنده شما برای بررسی ارسال شد. منتظر تایید مدیر باشید.",
        "en": "Your vendor profile has been submitted for review. Please wait for admin approval."
    },
    "notification.admin.vendor_pending.title": {
        "fa": "درخواست فروشنده جدید",
        "en": "New Vendor Request"
    },
    "notification.admin.vendor_pending.body": {
        "fa": "یک فروشنده جدید منتظر تایید است: {name}",
        "en": "A new vendor is awaiting approval: {name}"
    },
    "notification.admin.vendor_submitted.title": {
        "fa": "ارسال پروفایل فروشنده",
        "en": "Vendor Profile Submitted"
    },
    "notification.admin.vendor_submitted.body": {
        "fa": "فروشنده {vendor_name} با شماره {vendor_phone} پروفایل خود را برای بررسی ارسال کرده است.",
        "en": "Vendor {vendor_name} with phone number {vendor_phone} has submitted their profile for review."
    },
    "notification.vendor.active.title": {
        "fa": "پروفایل فروشنده فعال شد",
        "en": "Vendor Profile Activated"
    },
    "notification.vendor.active.body": {
        "fa": "پروفایل فروشنده شما با شماره {phone} اکنون فعال است. خوش آمدید!",
        "en": "Your vendor profile with phone {phone} is now active. Welcome!"
    },
    "notification.sent": {
        "fa": "نوتیفیکیشن با موفقیت ارسال شد",
        "en": "Notification sent successfully"
    },

    # General error messages
    "server.error": {
        "fa": "خطای سرور رخ داد.",
        "en": "Server error occurred."
    },
    "redis.error": {
        "fa": "سرویس ذخیره‌سازی موقتاً در دسترس نیست.",
        "en": "Storage service is temporarily unavailable."
    },
    "storage.error": {
        "fa": "خطا در ذخیره‌سازی داده‌های کد تایید.",
        "en": "Failed to store OTP data."
    },
    "invalid.result": {
        "fa": "نتیجه عملیات نامعتبر است.",
        "en": "Invalid operation result."
    },
    "invalid.status": {
        "fa": "وضعیت کاربر نامعتبر است.",
        "en": "Invalid user status."
    },
    "invalid.phone": {
        "fa": "شماره تلفن نامعتبر است.",
        "en": "Invalid phone number."
    },
    "invalid.language": {
        "fa": "زبان پشتیبانی‌نشده است. زبان‌های مجاز: {allowed}",
        "en": "Unsupported language. Allowed: {allowed}"
    },
    "invalid.request_id": {
        "fa": "شناسه درخواست بیش از حد طولانی است.",
        "en": "Request identifier is too long."
    },
    "invalid.client_version": {
        "fa": "فرمت نسخه کلاینت نامعتبر است. فرمت مورد انتظار: X.Y.Z",
        "en": "Invalid client version format. Expected format: X.Y.Z."
    },
    "invalid.device_fingerprint": {
        "fa": "فرمت اثر انگشت دستگاه نامعتبر است. از کاراکترهای الفبایی، عددی، خط تیره یا زیرخط استفاده کنید.",
        "en": "Invalid device fingerprint format. Use alphanumeric characters, hyphens, or underscores."
    },

    # Device-related messages
    "device.mismatch": {
        "fa": "دستگاه مشکوک شناسایی شد.",
        "en": "Suspicious device detected."
    },

    # Profile-related messages
    "profile.too_many": {
        "fa": "تعداد درخواست‌های تکمیل پروفایل بیش از حد است.",
        "en": "Too many profile completion requests."
    },

    # Admin-related messages
    "admin.user_joined": {
        "fa": {"title": "کاربر جدید", "body": "کاربر {user_name} با شماره {user_phone} به سیستم پیوست"},
        "en": {"title": "New User", "body": "User {user_name} with phone {user_phone} joined the system"}
    },

    # Account deletion messages
    "account.deletion.requested": {
        "fa": "درخواست حذف حساب شما ثبت شد. تیم پشتیبانی به زودی بررسی خواهد کرد.",
        "en": "Your account deletion request has been submitted. Support will review it soon."
    },

    # CSRF-related messages
    "csrf.missing": {
        "fa": "توکن CSRF ارسال نشده است.",
        "en": "CSRF token is missing."
    },
    "csrf.invalid": {
        "fa": "توکن CSRF معتبر نیست یا منقضی شده است.",
        "en": "CSRF token is invalid or expired."
    },
"otp.too_many.blocked": {
    "fa": "به دلیل تعداد بالای درخواست، موقتاً مسدود شده‌اید.",
    "en": "You are temporarily blocked due to too many requests."
}
}


def get_message(key: str, lang: Literal["fa", "en"] = "fa",
                variables: Optional[Dict[str, int | str]] = None) -> str | dict | None:
    """Retrieve a localized message based on key and language, with optional variable substitution."""
    message = MESSAGES.get(key, {}).get(lang) or MESSAGES.get(key, {}).get("en") or key
    if variables and isinstance(message, str):
        try:
            return message.format(**variables)
        except (KeyError, ValueError):
            return message
    if isinstance(message, dict):
        return message  # For messages with title/body structure
    return message