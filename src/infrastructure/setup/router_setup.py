# Path: src/api/v1/routers.py
from fastapi import FastAPI, APIRouter
from pathlib import Path
from importlib import import_module
from src.shared.config.settings import settings
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig

logger = LoggingService(LogConfig())


def setup_routers(app: FastAPI):
    """
    Automatically register all API routers from the src/api/v1/endpoints directory.

    Args:
        app: The FastAPI application instance.
    """
    base_router = APIRouter(tags=[settings.AUTH_TAG])

    routers_dir = Path(__file__).resolve().parent.parent.parent / "api" / "v1" / "endpoints"

    registered_count = 0

    if not routers_dir.exists():
        logger.error(
            "Routers directory not found, skipping router registration",
            context={"path": str(routers_dir)},
        )
        app.include_router(base_router)
        return

    logger.info("Scanning routers directory", context={"path": str(routers_dir)})

    for file_path in routers_dir.rglob("*.py"):
        if file_path.name.startswith("_"):
            logger.info("Skipping non-router file", context={"file": str(file_path)})
            continue

        relative_path = file_path.relative_to(routers_dir.parent.parent.parent).with_suffix("")
        module_path = f"src.{relative_path.as_posix().replace('/', '.')}"

        logger.info("Attempting to import module", context={"module_path": module_path})

        try:
            module = import_module(module_path)

            if hasattr(module, "router"):
                base_router.include_router(module.router)
                registered_count += 1
                logger.info(
                    "Registered router",
                    context={"module": module_path, "path": module.router.prefix or "/"},
                )
            else:
                logger.info(
                    "Skipped module without router",
                    context={"module": module_path},
                )

        except ImportError as e:
            logger.error(
                "Failed to import router module",
                context={"module": module_path, "error": str(e)},
            )
            continue
        except Exception as e:
            logger.error(
                "Unexpected error while registering router",
                context={"module": module_path, "error": str(e)},
            )
            continue

    app.include_router(base_router)

    if registered_count == 0:
        logger.info(
            "No routers were registered",
            context={"directory": str(routers_dir)},
        )
    else:
        logger.info(
            "All routers registered",
            context={
                "count": registered_count,
                "routes": [route.path for route in base_router.routes],
            },
        )