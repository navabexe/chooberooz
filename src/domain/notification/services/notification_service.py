from datetime import datetime, timezone
from typing import List, Dict, Union

from motor.motor_asyncio import AsyncIOMotorDatabase

from src.shared.errors.base import DatabaseConnectionException
from src.shared.utilities.logging import log_error, log_info
from src.domain.notification.models.notification import Notification, NotificationChannel
from src.domain.notification.services.builder import build_notification_content
from src.infrastructure.storage.nosql.client import get_nosql_db
from src.infrastructure.storage.nosql.repositories.base import MongoRepository


class NotificationService:
    async def _dispatch_notification(
        self,
        receiver_id: str,
        receiver_type: str,
        title: str,
        body: str,
        channel: NotificationChannel = NotificationChannel.INAPP,
        reference_type: str = None,
        reference_id: str = None,
        created_by: str = "system",
        db: AsyncIOMotorDatabase = None
    ) -> str:
        """Dispatch a notification to MongoDB and log it."""
        if channel != NotificationChannel.INAPP:
            raise ValueError(f"Channel {channel} not yet supported")

        # Ensure db is valid
        if db is None:
            db = await get_nosql_db()
            log_info("Fetched db instance in _dispatch_notification", extra={"db_fetched": True})

        try:
            notification = Notification(
                receiver_id=receiver_id,
                receiver_type=receiver_type,
                created_by=created_by,
                title=title,
                body=body,
                channel=channel,
                reference_type=reference_type,
                reference_id=reference_id,
                status="sent",
                sent_at=datetime.now(timezone.utc).isoformat()
            )

            notifications_repo = MongoRepository(db, "notifications")
            notification_id = await notifications_repo.insert_one(notification.model_dump(exclude_none=True))
            if not notification_id:
                raise DatabaseConnectionException(db_type="MongoDB", detail="Failed to insert notification")
            notification.id = str(notification_id)

            audit_repo = MongoRepository(db, "audit_logs")
            audit_id = await audit_repo.insert_one({
                "action": "notification_sent",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": {
                    "notification_id": notification_id,
                    "receiver_id": receiver_id,
                    "receiver_type": receiver_type,
                    "created_by": created_by,
                    "channel": channel.value
                }
            })
            if not audit_id:
                raise DatabaseConnectionException(db_type="MongoDB", detail="Failed to insert audit log")

            log_info("Notification dispatched", extra={
                "notification_id": notification_id,
                "receiver_id": receiver_id,
                "receiver_type": receiver_type,
                "channel": channel.value,
                "title": title,
                "created_by": created_by
            })
            return notification_id

        except DatabaseConnectionException as db_exc:
            raise
        except Exception as e:
            raise Exception(f"Failed to dispatch notification: {str(e)}")

    async def send(
        self,
        receiver_id: str,
        receiver_type: str,
        template_key: str,
        channel: NotificationChannel = NotificationChannel.INAPP,
        variables: dict = None,
        reference_type: str = None,
        reference_id: str = None,
        created_by: str = "system",
        language: str = "fa",
        return_bool: bool = False,
        additional_receivers: List[Dict[str, str]] = None,
        db: AsyncIOMotorDatabase = None,
        _is_retry: bool = False
    ) -> Union[str, bool]:
        """Send a notification with templated content."""
        try:
            content = await build_notification_content(
                template_key,
                language=language,
                variables=variables or {}
            )
            notification_id = await self._dispatch_notification(
                receiver_id=receiver_id,
                receiver_type=receiver_type,
                title=content["title"],
                body=content["body"],
                channel=channel,
                reference_type=reference_type,
                reference_id=reference_id,
                created_by=created_by,
                db=db
            )
            log_info("Notification sent successfully", extra={
                "receiver_id": receiver_id,
                "template_key": template_key,
                "notification_id": notification_id
            })

            for receiver in additional_receivers or []:
                await self.send(
                    receiver_id=receiver["id"],
                    receiver_type=receiver["type"],
                    template_key=template_key,
                    channel=channel,
                    variables=variables,
                    reference_type=reference_type,
                    reference_id=reference_id,
                    created_by=created_by,
                    language=language,
                    db=db
                )

            return True if return_bool else notification_id

        except ValueError as ve:
            log_error("Invalid template in notification", extra={
                "receiver_id": receiver_id,
                "template_key": template_key,
                "error": str(ve)
            })
            if not _is_retry and receiver_id != "admin":
                await self.send(
                    receiver_id="admin",
                    receiver_type="admin",
                    template_key="notification_failed",
                    variables={"receiver_id": receiver_id, "error": str(ve), "type": "template"},
                    reference_type="system",
                    reference_id=receiver_id,
                    language=language,
                    db=db,
                    _is_retry=True
                )
            if return_bool:
                return False
            raise

        except DatabaseConnectionException as db_exc:
            log_error("Database error in notification service", extra={
                "receiver_id": receiver_id,
                "template_key": template_key,
                "error": str(db_exc)
            })
            if not _is_retry and receiver_id != "admin":
                await self.send(
                    receiver_id="admin",
                    receiver_type="admin",
                    template_key="notification_failed",
                    variables={"receiver_id": receiver_id, "error": str(db_exc), "type": "database"},
                    reference_type="system",
                    reference_id=receiver_id,
                    language=language,
                    db=db,
                    _is_retry=True
                )
            if return_bool:
                return False
            raise

        except Exception as e:
            log_error("Notification service failed", extra={
                "receiver_id": receiver_id,
                "template_key": template_key,
                "error": str(e)
            })
            if not _is_retry and receiver_id != "admin":
                await self.send(
                    receiver_id="admin",
                    receiver_type="admin",
                    template_key="notification_failed",
                    variables={"receiver_id": receiver_id, "error": str(e), "type": "general"},
                    reference_type="system",
                    reference_id=receiver_id,
                    language=language,
                    db=db,
                    _is_retry=True
                )
            if return_bool:
                return False
            raise

    async def send_otp_verified(self, phone: str, role: str, language: str, db: AsyncIOMotorDatabase) -> bool:
        """Send notification for OTP verification."""
        return await self.send(
            receiver_id=phone,
            receiver_type=role,
            template_key="otp_verified",
            variables={"phone": phone, "role": role},
            reference_type="otp",
            reference_id=phone,
            language=language,
            return_bool=True,
            additional_receivers=[{"id": "admin", "type": "admin"}],
            db=db
        )

    async def send_session_notification(
        self,
        user_id: str,
        sessions: list,
        ip: str,
        language: str,
        db: AsyncIOMotorDatabase
    ) -> bool:
        """Send notification about session activity."""
        try:
            session_count = len(sessions)
            latest_session = None
            time = datetime.now(timezone.utc).isoformat()
            device = "unknown"

            if sessions:
                for s in sessions:
                    if not s.get("last_seen_at"):
                        s["last_seen_at"] = s.get("created_at", time)

                latest_session = max(sessions, key=lambda s: s.get("last_seen_at"))
                time = latest_session.get("last_seen_at", latest_session.get("created_at", time))
                device = latest_session.get("device_name", "unknown")

            user_content = await build_notification_content(
                template_key="sessions.checked",
                language=language,
                variables={
                    "ip": ip,
                    "time": time,
                    "count": session_count,
                    "device": device
                }
            )

            await self._dispatch_notification(
                receiver_id=user_id,
                receiver_type="user",
                title=user_content["title"],
                body=user_content["body"],
                channel=NotificationChannel.INAPP,
                reference_type="session",
                reference_id=user_id,
                db=db
            )

            ip_count = len(set(s.get("ip") or s.get("ip_address") for s in sessions if "ip" in s or "ip_address" in s))
            if session_count > 5 or ip_count > 3:
                admin_content = await build_notification_content(
                    template_key="sessions.danger",
                    language=language,
                    variables={
                        "user_id": user_id,
                        "ip": ip,
                        "count": session_count,
                        "ip_count": ip_count
                    }
                )

                await self._dispatch_notification(
                    receiver_id="admin",
                    receiver_type="admin",
                    title=admin_content["title"],
                    body=admin_content["body"],
                    channel=NotificationChannel.INAPP,
                    reference_type="session",
                    reference_id=user_id,
                    db=db
                )

            return True

        except Exception as e:
            log_error("Session notification failed", extra={
                "user_id": user_id,
                "ip": ip,
                "error": str(e)
            })
            if user_id != "admin":
                await self.send(
                    receiver_id="admin",
                    receiver_type="admin",
                    template_key="notification_failed",
                    variables={
                        "receiver_id": "admin",
                        "user_id": user_id,
                        "error": str(e),
                        "type": "general"
                    },
                    reference_type="session",
                    reference_id=user_id,
                    language=language,
                    db=db,
                    _is_retry=True
                )
            return False


notification_service = NotificationService()