"""API router initialization"""
from fastapi import APIRouter

# Import all routers
from app.api import clients, roles, groups

# Create main API router
api_router = APIRouter()

# Include sub-routers
api_router.include_router(clients.router, prefix="/clients", tags=["Clients"])
api_router.include_router(roles.router, prefix="/roles", tags=["Roles"])
api_router.include_router(groups.router, prefix="/groups", tags=["Groups"])
