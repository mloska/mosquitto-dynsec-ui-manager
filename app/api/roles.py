"""Role management endpoints"""
from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
import app.mosquitto_ctrl as mosquitto_ctrl
from app.models import (
    RoleListItem, RoleDetails, CreateRoleRequest, 
    AddACLRequest, SuccessResponse
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


@router.get("", response_model=List[RoleListItem])
async def list_roles(
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    List all roles on the Mosquitto server.
    
    Returns a list of role names.
    """
    server_ip, port = server_params
    success, roles = mosquitto_ctrl.get_dynsec_roles_via_mosquitto(server_ip, port)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to list roles from Mosquitto server")
    return roles


@router.get("/{role_name}", response_model=RoleDetails)
async def get_role(
    role_name: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Get detailed information about a specific role.
    
    Returns role details including all ACLs.
    """
    server_ip, port = server_params
    success, role = mosquitto_ctrl.get_role_via_mosquitto(server_ip, role_name, port)
    if not success:
        raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")
    return role


@router.post("", response_model=SuccessResponse)
async def create_role(
    data: CreateRoleRequest,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Create a new role.
    
    After creation, you can add ACLs to define permissions.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.create_role_via_mosquitto(
        server_ip, data.role_name, port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Role '{data.role_name}' created successfully")


@router.delete("/{role_name}", response_model=SuccessResponse)
async def delete_role(
    role_name: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Delete a role.
    
    This will remove the role from all clients and groups.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.delete_role_via_mosquitto(server_ip, role_name, port)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Role '{role_name}' deleted successfully")


@router.post("/{role_name}/acls", response_model=SuccessResponse)
async def add_role_acl(
    role_name: str,
    data: AddACLRequest,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Add an ACL (Access Control List) entry to a role.
    
    **ACL Types:**
    - `publishClientSend` - Allow client to publish messages
    - `publishClientReceive` - Allow client to receive published messages
    - `subscribeLiteral` - Allow subscription to exact topic
    - `subscribePattern` - Allow subscription to topic pattern (wildcards)
    - `unsubscribeLiteral` - Allow unsubscribing from exact topic
    - `unsubscribePattern` - Allow unsubscribing from topic pattern
    
    **Topic Patterns:**
    - Use `+` for single-level wildcard (e.g., `sensors/+/temperature`)
    - Use `#` for multi-level wildcard (e.g., `sensors/#`)
    """
    server_ip, port = server_params
    permission = "allow" if data.allow else "deny"
    success, message = mosquitto_ctrl.add_role_acl_via_mosquitto(
        server_ip, role_name, data.acl_type, data.topic, permission, port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(
        message=f"ACL added to role '{role_name}': {permission} {data.acl_type} on '{data.topic}'"
    )


@router.delete("/{role_name}/acls", response_model=SuccessResponse)
async def remove_role_acl(
    role_name: str,
    acl_type: str = Query(..., description="ACL type to remove"),
    topic: str = Query(..., description="Topic pattern to remove"),
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """
    Remove an ACL entry from a role.
    
    Specify the ACL type and topic pattern to remove.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.remove_role_acl_via_mosquitto(
        server_ip, role_name, acl_type, topic, port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(
        message=f"ACL removed from role '{role_name}': {acl_type} on '{topic}'"
    )
