"""Group management endpoints"""
from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
import app.mosquitto_ctrl as mosquitto_ctrl
from app.models import (
    GroupListItem, GroupDetails, CreateGroupRequest,
    AddGroupClientRequest, AddGroupRoleRequest, SuccessResponse
)
from app.auth import verify_credentials
from app.config import settings

router = APIRouter()


def get_server_params(
    server_ip: Optional[str] = Query(None, description="Mosquitto server IP/hostname (default from env)"),
    port: Optional[int] = Query(None, ge=1, le=65535, description="Mosquitto port (default from env)")
) -> tuple[str, int]:
    # Helper: resolve server connection parameters (query params or defaults)
    """Get server connection parameters, using defaults from config if not provided"""
    return (
        server_ip or settings.DEFAULT_MOSQUITTO_HOST,
        port or settings.DEFAULT_MOSQUITTO_PORT
    )


@router.get("", response_model=List[GroupListItem])
async def list_groups(
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    List all groups on the Mosquitto server.
    
    Returns a list of group names.
    """
    server_ip, port = server_params
    success, groups = mosquitto_ctrl.get_dynsec_groups_via_mosquitto(server_ip, port)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to list groups from Mosquitto server")
    return groups


@router.get("/{group_name}", response_model=GroupDetails)
async def get_group(
    group_name: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Get detailed information about a specific group.
    
    Returns group details including members and assigned roles.
    """
    server_ip, port = server_params
    success, group = mosquitto_ctrl.get_group_via_mosquitto(server_ip, group_name, port)
    if not success:
        raise HTTPException(status_code=404, detail=f"Group '{group_name}' not found")
    return group


@router.post("", response_model=SuccessResponse)
async def create_group(
    data: CreateGroupRequest,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Create a new group.
    
    After creation, you can add clients and roles to the group.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.create_group_via_mosquitto(
        server_ip, data.group_name, port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Group '{data.group_name}' created successfully")


@router.delete("/{group_name}", response_model=SuccessResponse)
async def delete_group(
    group_name: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Delete a group.
    
    This will remove all clients from the group.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.delete_group_via_mosquitto(server_ip, group_name, port)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Group '{group_name}' deleted successfully")


@router.post("/{group_name}/clients", response_model=SuccessResponse)
async def add_group_client(
    group_name: str,
    data: AddGroupClientRequest,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Add a client to a group.
    
    The client will inherit roles assigned to the group.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.add_group_client_via_mosquitto(
        server_ip, group_name, data.username, port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Client '{data.username}' added to group '{group_name}'")


@router.delete("/{group_name}/clients/{username}", response_model=SuccessResponse)
async def remove_group_client(
    group_name: str,
    username: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Remove a client from a group.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.remove_group_client_via_mosquitto(
        server_ip, group_name, username, port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Client '{username}' removed from group '{group_name}'")


@router.post("/{group_name}/roles", response_model=SuccessResponse)
async def add_group_role(
    group_name: str,
    data: AddGroupRoleRequest,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Add a role to a group.
    
    All clients in the group will inherit the role's ACLs.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.add_group_role_via_mosquitto(
        server_ip, group_name, data.role_name, str(data.priority), port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Role '{data.role_name}' added to group '{group_name}'")


@router.delete("/{group_name}/roles/{role_name}", response_model=SuccessResponse)
async def remove_group_role(
    group_name: str,
    role_name: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Remove a role from a group.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.remove_group_role_via_mosquitto(
        server_ip, group_name, role_name, port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Role '{role_name}' removed from group '{group_name}'")
