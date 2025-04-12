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
    base_router = APIRouter(prefix="/api", tags=[settings.AUTH_TAG])
    # Correct path to src/api/v1/endpoints
    routers_dir = Path(__file__).resolve().parent.parent.parent / "api" / "v1" / "endpoints"

    # Initialize a counter for registered routers
    registered_count = 0

    # Check if routers directory exists
    if not routers_dir.exists():
        log_error(
            "Routers directory not found, skipping router registration",
            extra={"path": str(routers_dir)},
        )
        app.include_router(base_router)
        return

    # Log the directory being scanned
    log_info("Scanning routers directory", extra={"path": str(routers_dir)})

    # Scan for Python files recursively
    for file_path in routers_dir.rglob("*.py"):
        # Skip unwanted files (like __init__.py)
        if file_path.name.startswith("_"):
            log_info(
                "Skipping non-router file",
                extra={"file": str(file_path)},
            )
            continue

        # Convert file path to module path
        relative_path = file_path.relative_to(routers_dir).with_suffix("")
        # Use posix path to ensure forward slashes (/) for module path
        module_path = f"src.api.v1.endpoints.{relative_path.as_posix().replace('/', '.')}"

        # Log the module path for debugging
        log_info("Attempting to import module", extra={"module_path": module_path})

        try:
            # Import the module
            module = import_module(module_path)

            # Check if module has a 'router' attribute
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
            )
            continue
        except Exception as e:
            log_error(
                "Unexpected error while registering router",
                extra={"module": module_path, "error": str(e)},
            )
            continue

    # Register the base router with the app
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