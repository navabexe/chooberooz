from fastapi import FastAPI, APIRouter
from pathlib import Path
from importlib import import_module
from src.shared.utilities.logging import log_info, log_error
from src.shared.config.settings import settings


def setup_routers(app: FastAPI):
    """
    Automatically register all API routers from the src/api/v1/endpoints directory.

    Scans for Python files in src/api/v1/endpoints and its subdirectories, imports
    modules containing a 'router' object, and registers them with the FastAPI app.

    Args:
        app: The FastAPI application instance.

    Notes:
        - Ignores files starting with '_'.
        - Logs each successful registration and any errors encountered.
        - If no routers are found, logs a warning but continues execution.
    """
    base_router = APIRouter(tags=[settings.AUTH_TAG])

    routers_dir = Path(__file__).resolve().parent.parent.parent / "api" / "v1" / "endpoints"

    registered_count = 0

    if not routers_dir.exists():
        log_error(
            "Routers directory not found, skipping router registration",
            extra={"path": str(routers_dir)},
        )
        app.include_router(base_router)
        return

    log_info("Scanning routers directory", extra={"path": str(routers_dir)})

    for file_path in routers_dir.rglob("*.py"):
        if file_path.name.startswith("_"):
            log_info("Skipping non-router file", extra={"file": str(file_path)})
            continue

        relative_path = file_path.relative_to(routers_dir.parent.parent.parent).with_suffix("")
        module_path = f"src.{relative_path.as_posix().replace('/', '.')}"

        log_info("Attempting to import module", extra={"module_path": module_path})

        try:
            module = import_module(module_path)

            if hasattr(module, "router"):
                base_router.include_router(module.router)
                registered_count += 1
                log_info(
                    "Registered router",
                    extra={"module": module_path, "path": module.router.prefix or "/"},
                )
            else:
                log_info(
                    "Skipped module without router",
                    extra={"module": module_path},
                )

        except ImportError as e:
            log_error(
                "Failed to import router module",
                extra={"module": module_path, "error": str(e)},
                exc_info=True
            )
            continue
        except Exception as e:
            log_error(
                "Unexpected error while registering router",
                extra={"module": module_path, "error": str(e)},
                exc_info=True
            )
            continue

    app.include_router(base_router)

    if registered_count == 0:
        log_info(
            "No routers were registered",
            extra={"directory": str(routers_dir)},
        )
    else:
        log_info(
            "All routers registered",
            extra={
                "count": registered_count,
                "routes": [route.path for route in base_router.routes],
            },
        )