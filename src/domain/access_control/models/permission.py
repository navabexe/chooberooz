from typing import Optional

from bson import ObjectId
from pydantic import BaseModel, Field, ConfigDict


class Permission(BaseModel):
    """Model representing a permission entity."""
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    name: str = Field(..., description="Unique name of the permission")
    description: Optional[str] = Field(default=None, description="Description of the permission")

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "_id": "60d0fe4f5311236168a109cb",
                "name": "read:products",
                "description": "Allows reading product data"
            }
        }
    )