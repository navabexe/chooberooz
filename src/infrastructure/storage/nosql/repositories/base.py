# Path: src/infrastructure/storage/nosql/repositories/base.py
from typing import Any, Dict, List, Optional, Tuple
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime

from src.shared.i18n.messages import get_message
from src.shared.errors.infrastructure.database import MongoError
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.utilities.types import LanguageCode
from src.shared.utilities.constants import HttpStatus


class MongoRepository:
    """Repository for MongoDB operations."""

    def __init__(self, db: AsyncIOMotorDatabase, collection_name: str):
        """Initialize repository with database and logger."""
        self.db = db
        self.collection = db[collection_name]
        self.logger = LoggingService(LogConfig())

    @staticmethod
    def _convert_to_objectid(value: Any) -> ObjectId:
        """Convert string to ObjectId if valid."""
        if isinstance(value, str) and ObjectId.is_valid(value):
            return ObjectId(value)
        return value

    @staticmethod
    def _serialize_update_fields(update: Dict[str, Any]) -> Dict[str, Any]:
        """Convert datetime objects in update dictionary to ISO format strings."""
        serialized = {}
        for key, value in update.items():
            if isinstance(value, datetime):
                serialized[key] = value.isoformat() + "Z"
            elif isinstance(value, dict):
                serialized[key] = MongoRepository._serialize_update_fields(value)  # برای دیکشنری‌های تودرتو
            else:
                serialized[key] = value
        return serialized

    async def insert_one(self, document: Dict[str, Any], language: LanguageCode = "en") -> str:
        """Insert a single document."""
        try:
            if "_id" in document and isinstance(document["_id"], str):
                document["_id"] = self._convert_to_objectid(document["_id"])
            result = await self.collection.insert_one(document)
            inserted_id = str(result.inserted_id)
            self.logger.info("Mongo insert_one", context={"collection": self.collection.name, "id": inserted_id})
            return inserted_id
        except Exception as e:
            self.logger.error("Mongo insert_one failed", context={"collection": self.collection.name, "error": str(e)})
            raise MongoError(
                operation="insert",
                error_code="MONGO_ERROR",
                message=get_message("mongo.insert.failed", language),
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"error": str(e)},
                language=language
            )

    async def find_one(self, query: Dict[str, Any], language: LanguageCode = "en") -> Optional[Dict[str, Any]]:
        """Find a single document."""
        try:
            if "_id" in query:
                query["_id"] = self._convert_to_objectid(query["_id"])
            result = await self.collection.find_one(query)
            if result:
                result["_id"] = str(result["_id"])
            self.logger.info("Mongo find_one",
                             context={"collection": self.collection.name, "query": str(query), "found": bool(result)})
            return result
        except Exception as e:
            self.logger.error("Mongo find_one failed", context={"collection": self.collection.name, "error": str(e)})
            raise MongoError(
                operation="find_one",
                error_code="MONGO_ERROR",
                message=get_message("mongo.find_one.failed", language),
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"error": str(e)},
                language=language
            )

    async def update_one(self, query: Dict[str, Any], update: Dict[str, Any], language: LanguageCode = "en") -> int:
        """Update a single document."""
        try:
            if "_id" in query:
                query["_id"] = self._convert_to_objectid(query["_id"])
            result = await self.collection.update_one(query, {"$set": update})
            serialized_update = self._serialize_update_fields(update)  # سریال‌سازی update
            self.logger.info("Mongo update_one",
                             context={"collection": self.collection.name, "query": str(query), "update": serialized_update,
                                      "modified": result.modified_count})
            return result.modified_count
        except Exception as e:
            self.logger.error("Mongo update_one failed", context={"collection": self.collection.name, "error": str(e)})
            raise MongoError(
                operation="update",
                error_code="MONGO_ERROR",
                message=get_message("mongo.update.failed", language),
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"error": str(e)},
                language=language
            )

    async def find(self, query: Dict[str, Any], language: LanguageCode = "en") -> List[Dict[str, Any]]:
        """Find multiple documents."""
        try:
            if "_id" in query:
                query["_id"] = self._convert_to_objectid(query["_id"])
            cursor = self.collection.find(query)
            result = await cursor.to_list(length=None)
            for doc in result:
                doc["_id"] = str(doc["_id"])
            self.logger.info("Mongo find",
                             context={"collection": self.collection.name, "query": str(query), "count": len(result)})
            return result
        except Exception as e:
            self.logger.error("Mongo find failed", context={"collection": self.collection.name, "error": str(e)})
            raise MongoError(
                operation="find",
                error_code="MONGO_ERROR",
                message=get_message("mongo.find.failed", language),
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"error": str(e)},
                language=language
            )

    async def find_with_pagination(self, query: Dict[str, Any], skip: int = 0, limit: int = 10,
                                   sort: Optional[List[Tuple[str, int]]] = None, language: LanguageCode = "en") -> List[
        Dict[str, Any]]:
        """Find documents with pagination."""
        try:
            if "_id" in query:
                query["_id"] = self._convert_to_objectid(query["_id"])
            cursor = self.collection.find(query).skip(skip).limit(limit)
            if sort:
                cursor = cursor.sort(sort)
            result = await cursor.to_list(length=limit)
            for doc in result:
                doc["_id"] = str(doc["_id"])
            self.logger.info("Mongo find_with_pagination",
                             context={"collection": self.collection.name, "query": str(query), "skip": skip,
                                      "limit": limit, "sort": sort, "count": len(result)})
            return result
        except Exception as e:
            self.logger.error("Mongo find_with_pagination failed",
                              context={"collection": self.collection.name, "error": str(e)})
            raise MongoError(
                operation="paginate",
                error_code="MONGO_ERROR",
                message=get_message("mongo.paginate.failed", language),
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"error": str(e)},
                language=language
            )

    async def delete_one(self, query: Dict[str, Any], language: LanguageCode = "en") -> int:
        """Delete a single document."""
        try:
            if "_id" in query:
                query["_id"] = self._convert_to_objectid(query["_id"])
            result = await self.collection.delete_one(query)
            self.logger.info("Mongo delete_one", context={"collection": self.collection.name, "query": str(query),
                                                          "deleted": result.deleted_count})
            return result.deleted_count
        except Exception as e:
            self.logger.error("Mongo delete_one failed", context={"collection": self.collection.name, "error": str(e)})
            raise MongoError(
                operation="delete",
                error_code="MONGO_ERROR",
                message=get_message("mongo.delete.failed", language),
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"error": str(e)},
                language=language
            )