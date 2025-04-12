from typing import Optional

from pydantic import BaseModel, Field, ConfigDict


class UserRole(BaseModel):
    """Model representing the assignment of a role to a user."""
    id: Optional[str] = Field(default=None, alias="_id", description="Unique identifier")
    user_id: str = Field(..., description="ID of the user")
    role_name: str = Field(..., description="Name of the assigned role")

    model_config = ConfigDict(
        populate_by_name=True
    )