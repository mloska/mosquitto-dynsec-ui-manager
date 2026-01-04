"""Client management endpoints.

This module exposes HTTP endpoints for managing MQTT clients via the
Mosquitto dynamic security plugin. Each route delegates to helper
functions in `app.mosquitto_ctrl` and is protected by the
`verify_credentials` dependency.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
import app.mosquitto_ctrl as mosquitto_ctrl
from app.models import (
    ClientListItem, ClientDetails, CreateClientRequest, 
    SetPasswordRequest, AddClientRoleRequest, SuccessResponse
)
from app.auth import verify_credentials
from app.config import settings

router = APIRouter()


def get_server_params(
    server_ip: Optional[str] = Query(None, description="Mosquitto server IP/hostname (default from env)"),
    port: Optional[int] = Query(None, ge=1, le=65535, description="Mosquitto port (default from env)")
) -> tuple[str, int]:
    """Resolve server connection parameters.

    If the client does not pass `server_ip` or `port` via query params,
    fall back to the defaults configured in `settings`.
    Returns a tuple of `(server_ip, port)`.
    """
    return (
        server_ip or settings.DEFAULT_MOSQUITTO_HOST,
        port or settings.DEFAULT_MOSQUITTO_PORT
    )


@router.get("", response_model=List[ClientListItem])
async def list_clients(
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """List all MQTT clients on the Mosquitto server.

    This endpoint returns a compact list of clients. For each client we
    attempt to fetch full details (roles and groups). If fetching details
    for a particular client fails, we still include the username so the
    list remains useful.
    """
    server_ip, port = server_params
    # Retrieve the raw clients list from the Mosquitto controller
    success, clients = mosquitto_ctrl.get_dynsec_clients_via_mosquitto(server_ip, port)
    if not success:
        # Bubble up a server error if the controller call fails
        raise HTTPException(status_code=500, detail="Failed to list clients from Mosquitto server")

    client_list = []
    for client in clients:
        # Each item in `clients` is expected to be a dict with a `username`
        username = client.get("username")
        # Try to enrich the list entry with groups and roles
        success, client_details = mosquitto_ctrl.get_client_via_mosquitto(server_ip, username, port)
        if success:
            client_list.append(ClientListItem(
                username=username,
                groups=client_details.get("groups", []),
                roles=client_details.get("roles", [])
            ))
        else:
            # If details are unavailable, still include the username
            client_list.append(ClientListItem(username=username))

    return client_list


@router.get("/{username}", response_model=ClientDetails)
async def get_client(
    username: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """Get detailed information about a single MQTT client.

    Returns a full client object including roles, groups and status
    information. If the client does not exist, a 404 is returned.
    """
    server_ip, port = server_params
    success, client = mosquitto_ctrl.get_client_via_mosquitto(server_ip, username, port)
    if not success:
        raise HTTPException(status_code=404, detail=f"Client '{username}' not found")
    return client


@router.post("", response_model=SuccessResponse)
async def create_client(
    data: CreateClientRequest,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """Create a new MQTT client with a username and password.

    The request body must include `username` and `password`. The
    underlying controller returns (success, message); on failure we
    translate this into a 400 response with the controller message.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.create_client_via_mosquitto(
        server_ip, data.username, data.password, port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Client '{data.username}' created successfully")


@router.delete("/{username}", response_model=SuccessResponse)
async def delete_client(
    username: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """Delete an MQTT client and revoke all access.

    The controller handles the deletion; translate failures to 400.
    """
    server_ip, port = server_params
    success, message = mosquitto_ctrl.delete_client_via_mosquitto(server_ip, username, port)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Client '{username}' deleted successfully")


@router.post("/{username}/enable", response_model=SuccessResponse)
async def enable_client(
    username: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """Enable a previously disabled client so it may reconnect."""
    server_ip, port = server_params
    success, message = mosquitto_ctrl.enable_client_via_mosquitto(server_ip, username, port)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Client '{username}' enabled successfully")


@router.post("/{username}/disable", response_model=SuccessResponse)
async def disable_client(
    username: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """Disable a client; they will be prevented from connecting."""
    server_ip, port = server_params
    success, message = mosquitto_ctrl.disable_client_via_mosquitto(server_ip, username, port)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Client '{username}' disabled successfully")


@router.put("/{username}/password", response_model=SuccessResponse)
async def set_client_password(
    username: str,
    data: SetPasswordRequest,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """Change a client's password. Client must reconnect with new password."""
    server_ip, port = server_params
    success, message = mosquitto_ctrl.set_client_password_via_mosquitto(
        server_ip, username, data.password, port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Password updated for client '{username}'")


@router.post("/{username}/roles", response_model=SuccessResponse)
async def add_client_role(
    username: str,
    data: AddClientRoleRequest,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """Assign an existing role to a client with a given priority."""
    server_ip, port = server_params
    success, message = mosquitto_ctrl.add_client_role_via_mosquitto(
        server_ip, username, data.role_name, str(data.priority), port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Role '{data.role_name}' added to client '{username}'")


@router.delete("/{username}/roles/{role_name}", response_model=SuccessResponse)
async def remove_client_role(
    username: str,
    role_name: str,
    server_params: tuple = Depends(get_server_params),
    _: str = Depends(verify_credentials)
):
    """Remove a role assignment from a client."""
    server_ip, port = server_params
    success, message = mosquitto_ctrl.remove_client_role_via_mosquitto(
        server_ip, username, role_name, port
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return SuccessResponse(message=f"Role '{role_name}' removed from client '{username}'")
