from fastapi import HTTPException, status


class AppHTTPException(HTTPException):
    def __init__(self, status_code: int, detail: str):
        super().__init__(status_code=status_code, detail=detail)


class TooManyRequestsException(AppHTTPException):
    def __init__(self, detail: str = "Too many requests. Please try again later."):
        super().__init__(status.HTTP_429_TOO_MANY_REQUESTS, detail)


class UnauthorizedException(AppHTTPException):
    def __init__(self, detail: str = "Unauthorized access."):
        super().__init__(status.HTTP_401_UNAUTHORIZED, detail)


class ForbiddenException(AppHTTPException):
    def __init__(self, detail: str = "You do not have permission to access this resource."):
        super().__init__(status.HTTP_403_FORBIDDEN, detail)


class NotFoundException(AppHTTPException):
    def __init__(self, detail: str = "Resource not found."):
        super().__init__(status.HTTP_404_NOT_FOUND, detail)


class BadRequestException(AppHTTPException):
    def __init__(self, detail: str = "Invalid request parameters."):
        super().__init__(status.HTTP_400_BAD_REQUEST, detail)


class ConflictException(AppHTTPException):
    def __init__(self, detail: str = "Resource conflict detected."):
        super().__init__(status.HTTP_409_CONFLICT, detail)


class InternalServerErrorException(AppHTTPException):
    def __init__(self, detail: str = "Internal server error occurred."):
        super().__init__(status.HTTP_500_INTERNAL_SERVER_ERROR, detail)


class ServiceUnavailableException(AppHTTPException):
    def __init__(self, detail: str = "Service temporarily unavailable. Please try again later."):
        super().__init__(status.HTTP_503_SERVICE_UNAVAILABLE, detail)


class DatabaseConnectionException(AppHTTPException):
    def __init__(self, db_type: str, detail: str = "Database connection failed. Please try again later."):
        super().__init__(status.HTTP_503_SERVICE_UNAVAILABLE, f"{db_type}: {detail}")


CUSTOM_HTTP_EXCEPTIONS = [
    TooManyRequestsException,
    UnauthorizedException,
    ForbiddenException,
    NotFoundException,
    BadRequestException,
    ConflictException,
    InternalServerErrorException,
    ServiceUnavailableException,
    DatabaseConnectionException,
]