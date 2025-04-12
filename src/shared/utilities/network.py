import aiohttp
from fastapi import Request
from user_agents import parse

from src.shared.config.settings import settings
from src.shared.utilities.logging import log_error


def parse_user_agent(user_agent: str) -> dict:
    agent = parse(user_agent)
    return {
        "device_type": "Mobile" if agent.is_mobile else "Tablet" if agent.is_tablet else "PC" if agent.is_pc else "Other",
        "os": agent.os.family or "Unknown",
        "browser": agent.browser.family or "Unknown",
        "device_name": agent.device.family or "Unknown Device"
    }


async def get_client_ip(request: Request) -> str:
    """Extract the client's IP address from the request headers or client host."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


async def get_location_from_ip(ip: str) -> str:
    """Get location from IP using ipinfo API."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://ipinfo.io/{ip}/json?token={settings.IPINFO_TOKEN}") as response:
                if response.status == 200:
                    data = await response.json()
                    city = data.get("city", "Unknown")
                    region = data.get("region", "")
                    country = data.get("country", "")
                    return f"{city}, {region}, {country}".strip(", ")
                else:
                    log_error("Failed to fetch location from ipinfo", extra={"ip": ip, "status": response.status})
                    return "Unknown"
    except Exception as e:
        log_error("Error fetching location from ipinfo", extra={"ip": ip, "error": str(e)})
        return "Unknown"

async def extract_client_ip(request: Request) -> str:
    """Extract the client's IP address from the request headers or client host."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host