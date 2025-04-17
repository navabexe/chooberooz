from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from src.infrastructure.storage.nosql.repositories.base import MongoRepository


class UserRepository:
    """Repository for managing user data in MongoDB."""
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    async def find_one(self, collection: str, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        repo = MongoRepository(self.db, collection)
        return await repo.find_one(query)

    async def find(self, collection: str, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        repo = MongoRepository(self.db, collection)
        return await repo.find(query)

    async def find_user(self, collection: str, phone: str) -> Optional[Dict[str, Any]]:
        repo = MongoRepository(self.db, collection)
        return await repo.find_one({"phone": phone})

    async def insert_user(self, collection: str, user_data: Dict[str, Any]) -> str:
        repo = MongoRepository(self.db, collection)
        return await repo.insert_one(user_data)

    async def update_user(self, collection: str, user_id: str, update_fields: Dict[str, Any]) -> int:
        repo = MongoRepository(self.db, collection)
        return await repo.update_one({"_id": user_id}, update_fields)

    async def update_one(self, collection: str, query: Dict[str, Any], update_data: Dict[str, Any]) -> int:
        repo = MongoRepository(self.db, collection)
        return await repo.update_one(query, update_data)

    async def log_audit(self, action: str, details: Dict[str, Any]) -> str:
        repo = MongoRepository(self.db, "audit_logs")
        audit_data = {
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details
        }
        return await repo.insert_one(audit_data)