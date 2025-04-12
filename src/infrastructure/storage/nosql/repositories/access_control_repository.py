from typing import List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from src.shared.utilities.logging import log_error
from src.domain.access_control.models.permission import Permission
from src.domain.access_control.models.role import Role
from src.domain.access_control.models.user_role import UserRole


class MongoAccessControlRepository:
    """Repository for managing roles, permissions, and user-role assignments in MongoDB."""
    def __init__(self, db: AsyncIOMotorDatabase):
        self.roles = db["roles"]
        self.permissions = db["permissions"]
        self.user_roles = db["user_roles"]

    async def create_permission(self, permission: Permission) -> str:
        """Create a new permission."""
        result = await self.permissions.insert_one(permission.model_dump(by_alias=True))
        return str(result.inserted_id)

    async def create_role(self, role: Role) -> str:
        """Create a new role."""
        result = await self.roles.insert_one(role.model_dump(by_alias=True))
        return str(result.inserted_id)

    async def get_role_by_name(self, name: str) -> Optional[Role]:
        """Retrieve a role by its name."""
        doc = await self.roles.find_one({"name": name})
        return Role(**doc) if doc else None

    async def list_roles(self) -> List[Role]:
        """List all roles."""
        cursor = self.roles.find()
        return [Role(**doc) async for doc in cursor]

    async def list_permissions(self) -> List[Permission]:
        """List all permissions."""
        cursor = self.permissions.find()
        return [Permission(**doc) async for doc in cursor]

    async def assign_role_to_user(self, user_id: str, role_name: str) -> str:
        """Assign a role to a user."""
        user_role = UserRole(user_id=user_id, role_name=role_name)
        try:
            result = await self.user_roles.insert_one(user_role.model_dump(by_alias=True))
            return str(result.inserted_id)
        except Exception as e:
            log_error("Failed to assign role", extra={"error": str(e)})
            raise

    async def get_user_role(self, user_id: str) -> Optional[str]:
        """Retrieve the role assigned to a user."""
        doc = await self.user_roles.find_one({"user_id": user_id})
        return doc["role_name"] if doc else None