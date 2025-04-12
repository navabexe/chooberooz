from datetime import datetime, UTC
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, ConfigDict


class NotificationChannel(str, Enum):
    """Available channels for sending notifications."""
    PUSH = "push"
    SMS = "sms"
    EMAIL = "email"
    INAPP = "inapp"


class NotificationStatus(str, Enum):
    """Possible statuses for a notification."""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    READ = "read"


class Notification(BaseModel):
    """Model representing a notification entity."""
    id: Optional[str] = Field(default=None, alias="_id")
    receiver_id: str = Field(..., description="ID of the target user/vendor/admin")
    receiver_type: str = Field(..., description="Type of receiver: user, vendor, or admin")
    created_by: Optional[str] = Field(default=None, description="ID of the sender (e.g., system or admin)")
    title: str = Field(..., description="Notification title")
    body: str = Field(..., description="Notification body")
    channel: NotificationChannel = Field(default=NotificationChannel.INAPP, description="Delivery channel")
    status: NotificationStatus = Field(default=NotificationStatus.PENDING, description="Notification status")
    reference_type: Optional[str] = Field(default=None, description="Type of referenced entity")
    reference_id: Optional[str] = Field(default=None, description="ID of referenced entity")
    sent_at: Optional[str] = Field(default=None, description="Time the notification was sent")
    read_at: Optional[str] = Field(default=None, description="Time the notification was read")
    created_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="Creation time of the notification"
    )

    model_config = ConfigDict(
        populate_by_name=True,
        json_encoders={
            datetime: lambda v: v.isoformat()
        }
    )