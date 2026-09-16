"""API v1 routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.core.settings import settings

api_router = APIRouter()


@api_router.get("/health")
async def health() -> dict[str, Any]:
    """Health check for API versioned router."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
    }


@api_router.get("/info")
async def info() -> dict[str, Any]:
    """Static API information for diagnostics."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
    }
