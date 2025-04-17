from datetime import datetime, UTC
from typing import List, Optional

from pydantic import BaseModel, Field, ConfigDict

from src.shared.utilities.time import utc_now


class Role(BaseModel):
    """Model representing a role entity."""
    id: Optional[str] = Field(default=None, alias="_id", description="Unique identifier")
    name: str = Field(..., description="Unique name of the role")
    description: Optional[str] = Field(default=None, description="Description of the role")
    permissions: List[str] = Field(default_factory=list, description="List of permission IDs")
    users_count: int = Field(default=0, description="Number of users assigned to this role")
    created_by: Optional[str] = Field(default=None, description="ID of the creator")
    created_at: str = Field(
        default_factory=lambda: utc_now(),
        description="Creation timestamp"
    )
    updated_by: Optional[str] = Field(default=None, description="ID of the last updater")
    updated_at: str = Field(
        default_factory=lambda: utc_now(),
        description="Last update timestamp"
    )

    model_config = ConfigDict(
        populate_by_name=True,
        json_encoders={
            datetime: lambda v: v.isoformat()
        }
    )