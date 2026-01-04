"""Pydantic models for request/response validation"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class SuccessResponse(BaseModel):
    """Standard success response"""
    success: bool = True
    message: str


class ErrorResponse(BaseModel):
    """Standard error response"""
    success: bool = False
    detail: str


# ============================================
# Client Models
# ============================================

class ClientListItem(BaseModel):
    """Client list item"""
    username: str
    groups: List[Dict[str, Any]] = []
    roles: List[Dict[str, Any]] = []


class ClientDetails(BaseModel):
    """Detailed client information"""
    username: str
    clientid: str
    disabled: bool
    textname: Optional[str] = None
    roles: List[Dict[str, Any]] = []
    groups: List[str] = []


class CreateClientRequest(BaseModel):
    """Request to create a new client"""
    username: str = Field(..., min_length=1, max_length=100, description="MQTT client username")
    password: str = Field(..., min_length=8, description="Client password (min 8 characters)")
    textname: Optional[str] = Field(None, description="Optional display name")
    textdescription: Optional[str] = Field(None, description="Optional description")


class SetPasswordRequest(BaseModel):
    """Request to change client password"""
    password: str = Field(..., min_length=8, description="New password (min 8 characters)")


class AddClientRoleRequest(BaseModel):
    """Request to add a role to a client"""
    role_name: str = Field(..., description="Name of the role to add")
    priority: int = Field(1, ge=-1, description="Role priority (-1 = highest)")


# ============================================
# Role Models
# ============================================

class RoleListItem(BaseModel):
    """Role list item"""
    rolename: str


class ACLItem(BaseModel):
    """ACL entry"""
    acltype: str
    topic: str
    allow: bool
    priority: int = 1


class RoleDetails(BaseModel):
    """Detailed role information"""
    rolename: str
    textname: Optional[str] = None
    textdescription: Optional[str] = None
    acls: List[ACLItem] = []


class CreateRoleRequest(BaseModel):
    """Request to create a new role"""
    role_name: str = Field(..., min_length=1, max_length=100, description="Role name")
    textname: Optional[str] = Field(None, description="Optional display name")
    textdescription: Optional[str] = Field(None, description="Optional description")


class AddACLRequest(BaseModel):
    """Request to add an ACL to a role"""
    acl_type: str = Field(
        ...,
        description="ACL type: publishClientSend, publishClientReceive, subscribeLiteral, subscribePattern, unsubscribeLiteral, unsubscribePattern"
    )
    topic: str = Field(..., description="MQTT topic pattern")
    allow: bool = Field(True, description="Allow or deny")
    priority: int = Field(1, ge=-1, description="ACL priority (-1 = highest)")


# ============================================
# Group Models
# ============================================

class GroupListItem(BaseModel):
    """Group list item"""
    groupname: str


class GroupDetails(BaseModel):
    """Detailed group information"""
    groupname: str
    textname: Optional[str] = None
    textdescription: Optional[str] = None
    clients: List[str] = []
    roles: List[Dict[str, Any]] = []


class CreateGroupRequest(BaseModel):
    """Request to create a new group"""
    group_name: str = Field(..., min_length=1, max_length=100, description="Group name")
    textname: Optional[str] = Field(None, description="Optional display name")
    textdescription: Optional[str] = Field(None, description="Optional description")


class AddGroupClientRequest(BaseModel):
    """Request to add a client to a group"""
    username: str = Field(..., description="Client username to add")


class AddGroupRoleRequest(BaseModel):
    """Request to add a role to a group"""
    role_name: str = Field(..., description="Role name to add")
    priority: int = Field(1, ge=-1, description="Role priority (-1 = highest)")


# ============================================
# Server Connection
# ============================================

class ServerConnection(BaseModel):
    """Mosquitto server connection parameters (optional query params)"""
    server_ip: Optional[str] = Field(None, description="Mosquitto server IP/hostname")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Mosquitto port")
