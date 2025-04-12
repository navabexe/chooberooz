from fastapi import APIRouter

from src.api.v1.endpoints.auth.otp_request import router as otp_request_router
from src.api.v1.endpoints.auth.otp_verify import router as otp_verify_router

all_routers = APIRouter(prefix="/api", tags=["all"])

all_routers.include_router(otp_request_router)
all_routers.include_router(otp_verify_router)