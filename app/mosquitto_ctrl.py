import shutil
import subprocess
import logging
import os
import re  # Added for improved ACL parsing
from typing import Optional, Tuple, List, Dict, Any

logger = logging.getLogger(__name__)

# =====================================================
# Helpers / Parsing
# =====================================================

def _parse_simple_list(output: str, header_prefix: str, key: str) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(header_prefix):
            continue
        items.append({key: line})
    return items

def parse_client_list(output: str) -> List[Dict[str, str]]:
    return _parse_simple_list(output, "Client", "username")

def parse_role_list(output: str) -> List[Dict[str, str]]:
    return _parse_simple_list(output, "Role", "rolename")

def parse_group_list(output: str) -> List[Dict[str, str]]:
    return _parse_simple_list(output, "Group", "groupname")

def parse_default_acl(output: str) -> Dict[str, bool]:
    acl_info = {
        "publishClientSend": False,
        "publishClientReceive": False,
        "subscribe": False,
        "unsubscribe": False,
    }
    for raw in output.splitlines():
        line = raw.strip().lower()
        if not line:
            continue
        if "publish client send" in line:
            acl_info["publishClientSend"] = "allow" in line
        elif "publish client receive" in line:
            acl_info["publishClientReceive"] = "allow" in line
        elif "subscribe" in line and "unsubscribe" not in line:
            acl_info["subscribe"] = "allow" in line
        elif "unsubscribe" in line:
            acl_info["unsubscribe"] = "allow" in line
    return acl_info

def parse_client_details(output: str) -> Dict[str, Any]:
    client_info: Dict[str, Any] = {
        "username": "",
        "clientid": "",
        "roles": [],
        "groups": [],
        "disabled": False,
        "textname": "",
    }
    current_section: Optional[str] = None  # 'roles' or 'groups'

    def parse_name_priority(s: str) -> (str, str):
        s = s.strip()
        # remove bullet markers if present
        s = s.lstrip('-* ').strip()
        if not s:
            return "", "0"
        name = s
        priority = "0"
        if "(" in s and ")" in s and "priority:" in s:
            parts = s.split("(")
            name = parts[0].strip()
            try:
                priority = parts[1].split(")")[0].replace("priority:", "").strip()
            except Exception:
                priority = "0"
        return name, priority

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("username:"):
            client_info["username"] = line.split(":", 1)[1].strip()
            current_section = None
        elif low.startswith("client id:"):
            client_info["clientid"] = line.split(":", 1)[1].strip()
            current_section = None
        elif low.startswith("text name:") or low.startswith("textname:"):
            client_info["textname"] = line.split(":", 1)[1].strip()
            current_section = None
        elif low.startswith("disabled:"):
            client_info["disabled"] = "true" in low
            current_section = None
        elif low.startswith("roles:"):
            current_section = "roles"
            item = line.split(":", 1)[1].strip()
            if item and item.lower() != "none":
                name, prio = parse_name_priority(item)
                if name:
                    client_info["roles"].append({"rolename": name, "priority": prio})
        elif low.startswith("groups:"):
            current_section = "groups"
            item = line.split(":", 1)[1].strip()
            if item and item.lower() != "none":
                name, prio = parse_name_priority(item)
                if name:
                    client_info["groups"].append({"groupname": name, "priority": prio})
        else:
            # Continuation lines belonging to the last seen section
            if current_section in ("roles", "groups"):
                name, prio = parse_name_priority(line)
                if name:
                    if current_section == "roles":
                        client_info["roles"].append({"rolename": name, "priority": prio})
                    else:
                        client_info["groups"].append({"groupname": name, "priority": prio})
            # Otherwise ignore line
    return client_info

def parse_role_details(output: str, role_name: str) -> Dict[str, Any]:
    role_info: Dict[str, Any] = {"rolename": role_name, "acls": []}
    # Regex to match common mosquitto dynsec ACL line formats, examples:
    # publishClientSend allow sensors/temperature (priority: 1)
    # subscribePattern deny sensors/# (priority:2)
    # publishLiteral allow foo/bar
    acl_regex = re.compile(r"^(?P<acltype>\S+)\s+(?P<permission>allow|deny)\s+(?P<topic>[^()]+?)(?:\s*\(priority:\s*(?P<priority>\d+)\))?\s*$", re.IGNORECASE)
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        # Skip header-ish lines
        if low.startswith("role:") or low == "acls:" or low == "acls" or low.startswith("role "):
            continue
        # Some versions may prefix with '-' or '*'
        line_clean = line.lstrip('-* ').strip()
        m = acl_regex.match(line_clean)
        if m:
            acltype = m.group('acltype')
            permission = m.group('permission').lower()
            topic = m.group('topic').strip()
            priority = m.group('priority') or '0'
            try:
                p_int = int(priority)
            except ValueError:
                p_int = 0
            role_info["acls"].append({
                "topic": topic,
                "acltype": acltype,
                "allow": permission == "allow",
                "priority": p_int,
            })
            continue
        # Fallback: original colon-splitting logic (legacy format)
        if ("ACLs:" in line) or (any(t in line for t in ["publishClientSend", "subscribeLiteral", "subscribePattern", "publishLiteral", "publishPattern", "publishClientReceive", "unsubscribe", "subscribe"])):
            # Remove a leading 'ACLs:' if present
            acl_part = line.split("ACLs:", 1)[1].strip() if "ACLs:" in line else line
            parts = [p.strip() for p in acl_part.split(":")]
            if len(parts) >= 3:
                acl_type = parts[0]
                permission = parts[1].lower()
                topic_and_priority = parts[2]
                topic = topic_and_priority.split("(")[0].strip()
                priority = "0"
                if "(priority:" in topic_and_priority:
                    priority = topic_and_priority.split("priority:", 1)[1].strip(") ")
                try:
                    p_int = int(priority)
                except ValueError:
                    p_int = 0
                role_info["acls"].append({
                    "topic": topic,
                    "acltype": acl_type,
                    "allow": permission == "allow",
                    "priority": p_int,
                })
    if not role_info["acls"]:
        logger.debug("No ACLs parsed for role '%s'. Raw output:\n%s", role_name, output)
    return role_info

def parse_group_details(output: str, group_name: str) -> Dict[str, Any]:
    group_info: Dict[str, Any] = {"groupname": group_name, "roles": [], "clients": [], "textname": ""}
    current_section: Optional[str] = None  # 'roles' or 'clients'

    def parse_name_priority(s: str) -> (str, str):
        s = s.strip()
        s = s.lstrip('-* ').strip()
        if not s:
            return "", "0"
        name = s
        priority = "0"
        if "(" in s and ")" in s and "priority:" in s:
            parts = s.split("(")
            name = parts[0].strip()
            try:
                priority = parts[1].split(")")[0].replace("priority:", "").strip()
            except Exception:
                priority = "0"
        return name, priority

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("group:"):
            # ignore, we already have name from arg
            current_section = None
            continue
        if low.startswith("text name:") or low.startswith("textname:"):
            group_info["textname"] = line.split(":", 1)[1].strip()
            current_section = None
            continue
        if low.startswith("roles:"):
            current_section = "roles"
            item = line.split(":", 1)[1].strip()
            if item and item.lower() != "none":
                name, prio = parse_name_priority(item)
                if name:
                    group_info["roles"].append({"rolename": name, "priority": prio})
            continue
        if low.startswith("clients:"):
            current_section = "clients"
            item = line.split(":", 1)[1].strip()
            if item and item.lower() != "none":
                name, prio = parse_name_priority(item)
                if name:
                    group_info["clients"].append({"username": name, "priority": prio})
            continue

        # Continuations
        if current_section == "roles":
            name, prio = parse_name_priority(line)
            if name:
                group_info["roles"].append({"rolename": name, "priority": prio})
            continue
        if current_section == "clients":
            name, prio = parse_name_priority(line)
            if name:
                group_info["clients"].append({"username": name, "priority": prio})
            continue

    return group_info

# Mosquitto Dynamic Security Control Configuration
def get_dynsec_base_command(
    server_ip: Optional[str],
    port: int = 1883,
    use_tls: bool = False,
    cafile: Optional[str] = None,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    insecure: bool = False
) -> List[str]:
    """
    Get base mosquitto_ctrl command for specific server (server_ip is required).
    
    Args:
        server_ip: Server IP address or hostname
        port: MQTT port (default 1883 for plain, 8883 for TLS)
        use_tls: Enable TLS/SSL (auto-enabled if port is 8883)
        cafile: Path to CA certificate file for TLS
        certfile: Path to client certificate file for TLS
        keyfile: Path to client key file for TLS
        insecure: Disable certificate verification (not recommended for production)
    """
    if not server_ip:
        raise ValueError("server_ip is required (no default).")
    
    # Auto-enable TLS if port is 8883
    if port == 8883:
        use_tls = True
    
    # Get credentials from environment variables
    username = os.getenv("MOSQUITTO_ADMIN_USERNAME", "admin")
    password = os.getenv("MOSQUITTO_ADMIN_PASSWORD", "passadmin")
    
    # Get TLS settings from environment variables if not explicitly provided
    if use_tls and not cafile:
        cafile = os.getenv("MOSQUITTO_CAFILE", None)
    if use_tls and not certfile:
        certfile = os.getenv("MOSQUITTO_CERTFILE", None)
    if use_tls and not keyfile:
        keyfile = os.getenv("MOSQUITTO_KEYFILE", None)
    if not insecure:
        insecure = os.getenv("MOSQUITTO_INSECURE", "false").lower() == "true"
    
    command = [
        "mosquitto_ctrl",
        "-h", server_ip,
        "-p", str(port),
        "-u", username,
        "-P", password
    ]
    
    # Add TLS options if enabled
    if use_tls:
        if cafile:
            command.extend(["--cafile", cafile])
        if certfile:
            command.extend(["--cert", certfile])
        if keyfile:
            command.extend(["--key", keyfile])
        if insecure:
            command.append("--insecure")
            logger.warning("TLS certificate verification disabled (--insecure). Not recommended for production.")
    
    return command

def check_mosquitto_ctrl_available() -> bool:
    """Check if mosquitto_ctrl command is available in the system"""
    try:
        if shutil.which("mosquitto_ctrl") is not None:
            result = subprocess.run(["mosquitto_ctrl", "--help"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 or "mosquitto_ctrl" in result.stdout or "mosquitto_ctrl" in result.stderr:
                logger.debug("mosquitto_ctrl is available")
                return True
            logger.warning("mosquitto_ctrl found but returned non-zero exit code: %s, stderr: %s", result.returncode, result.stderr)
        else:
            logger.error("mosquitto_ctrl command not found in PATH. Install mosquitto-clients package: apt-get install mosquitto-clients")
    except subprocess.TimeoutExpired:
        logger.error("mosquitto_ctrl --help timed out")
    except Exception as e:
        logger.error(f"Error checking mosquitto_ctrl availability: {str(e)}")
    return False

def execute_mosquitto_command(
    command: List[str],
    server_ip: Optional[str],
    port: int = 1883,
    input_data: Optional[str] = None,
    use_tls: bool = False,
    cafile: Optional[str] = None,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    insecure: bool = False
) -> Tuple[bool, str]:
    """
    Execute mosquitto_ctrl command and return success status and output
    
    Args:
        command: mosquitto_ctrl command arguments (e.g., ["dynsec", "listClients"])
        server_ip: MQTT broker IP/hostname
        port: MQTT broker port (1883 or 8883)
        input_data: Optional stdin data
        use_tls: Enable TLS/SSL (auto-enabled if port is 8883)
        cafile: Path to CA certificate file
        certfile: Path to client certificate file
        keyfile: Path to client key file
        insecure: Disable certificate verification
    """
    if not check_mosquitto_ctrl_available():
        logger.error("mosquitto_ctrl is not available in this environment - make sure mosquitto-clients package is installed")
        return False, "mosquitto_ctrl command not found - install mosquitto-clients package"
    if not server_ip:
        msg = "server_ip is required but was not provided."
        logger.error(msg)
        return False, msg
    try:
        base_command = get_dynsec_base_command(server_ip, port, use_tls, cafile, certfile, keyfile, insecure)
        full_command = base_command + command
        # Enhanced structured logging (hide password in logs)
        cmd_display = [x if x != base_command[-1] else "****" for x in full_command]
        logger.debug(f"Executing mosquitto_ctrl command to {server_ip}:{port}: {' '.join(cmd_display)}")
        
        process = subprocess.Popen(
            full_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate(input=input_data, timeout=10)
        
        if process.returncode == 0:
            logger.debug(f"Command succeeded, output length: {len(stdout)} chars")
            return True, stdout.strip()
        else:
            error_msg = stderr.strip() if stderr.strip() else f"Command returned exit code {process.returncode}"
            logger.error(f"mosquitto_ctrl command failed: {error_msg}")
            # Provide better error messages for common issues
            if "connection refused" in error_msg.lower() or "refused" in error_msg.lower():
                error_msg = f"Cannot connect to Mosquitto at {server_ip}:{port}. Check if broker is running and accessible."
            elif "authentication failed" in error_msg.lower() or "permission denied" in error_msg.lower():
                error_msg = f"Authentication failed for user 'admin'. Check MOSQUITTO_ADMIN_USERNAME and MOSQUITTO_ADMIN_PASSWORD environment variables."
            elif "certificate" in error_msg.lower() or "tls" in error_msg.lower() or "ssl" in error_msg.lower():
                error_msg = f"TLS/SSL error connecting to {server_ip}:{port}. Check certificate settings."
            return False, error_msg
    except subprocess.TimeoutExpired:
        logger.error(f"mosquitto_ctrl command timed out connecting to {server_ip}:{port}")
        return False, f"Connection to Mosquitto at {server_ip}:{port} timed out. Broker may be unavailable."
    except FileNotFoundError:
        logger.error(f"mosquitto_ctrl executable not found - install mosquitto-clients package")
        return False, "mosquitto_ctrl executable not found - install mosquitto-clients package"
    except Exception as e:
        logger.error(f"Error executing mosquitto_ctrl command: {str(e)}")
        return False, f"Error: {str(e)}"

def get_dynsec_clients_via_mosquitto(server_ip: Optional[str], port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, list]:
    # Removed duplicate server_ip check (handled in execute)
    success, output = execute_mosquitto_command(["dynsec", "listClients"], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)
    if success:
        try:
            return True, parse_client_list(output)
        except Exception as e:
            logger.error("Failed to parse client list: %s", e)
    return False, []

def get_dynsec_roles_via_mosquitto(server_ip: Optional[str], port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, list]:
    success, output = execute_mosquitto_command(["dynsec", "listRoles"], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)
    if success:
        try:
            return True, parse_role_list(output)
        except Exception as e:
            logger.error("Failed to parse role list: %s", e)
    return False, []

def get_dynsec_groups_via_mosquitto(server_ip: Optional[str], port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, list]:
    success, output = execute_mosquitto_command(["dynsec", "listGroups"], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)
    if success:
        try:
            return True, parse_group_list(output)
        except Exception as e:
            logger.error("Failed to parse group list: %s", e)
    return False, []

def get_dynsec_default_acl_via_mosquitto(server_ip: Optional[str], port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, dict]:
    success, output = execute_mosquitto_command(["dynsec", "getDefaultACLAccess"], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)
    if success:
        try:
            return True, parse_default_acl(output)
        except Exception as e:
            logger.error("Failed to parse default ACL: %s", e)
    return False, {}

# Client Management Functions
def create_client_via_mosquitto(server_ip: Optional[str], username: str, password: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Create a new client via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    # Create client
    success, result = execute_mosquitto_command(["dynsec", "createClient", username], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)
    if not success:
        return False, result
    
    # Set password
    success, result = execute_mosquitto_command(["dynsec", "setClientPassword", username, password], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)
    if not success:
        # Cleanup created client if password setting fails
        execute_mosquitto_command(["dynsec", "deleteClient", username], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)
        return False, result
    
    return True, f"Client {username} created successfully"

def get_client_via_mosquitto(server_ip: Optional[str], username: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, dict]:
    success, output = execute_mosquitto_command(["dynsec", "getClient", username], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)
    if not success:
        return False, {}
    try:
        return True, parse_client_details(output)
    except Exception as e:
        logger.error("Failed to parse client details: %s", e)
        return False, {}

def enable_client_via_mosquitto(server_ip: Optional[str], username: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Enable a client via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "enableClient", username], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def disable_client_via_mosquitto(server_ip: Optional[str], username: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Disable a client via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "disableClient", username], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def delete_client_via_mosquitto(server_ip: Optional[str], username: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Delete a client via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "deleteClient", username], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def set_client_password_via_mosquitto(server_ip: Optional[str], username: str, password: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Set client password via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "setClientPassword", username, password], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

# Role Management Functions
def create_role_via_mosquitto(server_ip: Optional[str], role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Create a new role via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "createRole", role_name], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def get_role_via_mosquitto(server_ip: Optional[str], role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, dict]:
    success, output = execute_mosquitto_command(["dynsec", "getRole", role_name], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)
    if not success:
        return False, {}
    try:
        return True, parse_role_details(output, role_name)
    except Exception as e:
        logger.error("Failed to parse role details: %s", e)
        return False, {}

def delete_role_via_mosquitto(server_ip: Optional[str], role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Delete a role via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "deleteRole", role_name], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def add_role_acl_via_mosquitto(server_ip: Optional[str], role_name: str, acl_type: str, topic: str, permission: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Add an ACL to a role via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "addRoleACL", role_name, acl_type, topic, permission], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def remove_role_acl_via_mosquitto(server_ip: Optional[str], role_name: str, acl_type: str, topic: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Remove an ACL from a role via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "removeRoleACL", role_name, acl_type, topic], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

# Client-Role Management Functions
def add_client_role_via_mosquitto(server_ip: Optional[str], username: str, role_name: str, priority: str = "1", port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Add a role to a client via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "addClientRole", username, role_name, priority], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def remove_client_role_via_mosquitto(server_ip: Optional[str], username: str, role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Remove a role from a client via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "removeClientRole", username, role_name], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

# Group Management Functions  
def create_group_via_mosquitto(server_ip: Optional[str], group_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Create a new group via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "createGroup", group_name], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def get_group_via_mosquitto(server_ip: Optional[str], group_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, dict]:
    success, output = execute_mosquitto_command(["dynsec", "getGroup", group_name], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)
    if not success:
        return False, {}
    try:
        return True, parse_group_details(output, group_name)
    except Exception as e:
        logger.error("Failed to parse group details: %s", e)
        return False, {}

def delete_group_via_mosquitto(server_ip: Optional[str], group_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Delete a group via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "deleteGroup", group_name], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def add_group_role_via_mosquitto(server_ip: Optional[str], group_name: str, role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Add a role to a group via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "addGroupRole", group_name, role_name], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def remove_group_role_via_mosquitto(server_ip: Optional[str], group_name: str, role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Remove a role from a group via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "removeGroupRole", group_name, role_name], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def add_group_client_via_mosquitto(server_ip: Optional[str], group_name: str, username: str, priority: str = "1", port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Add a client to a group via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "addGroupClient", group_name, username, priority], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

def remove_group_client_via_mosquitto(server_ip: Optional[str], group_name: str, username: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Remove a client from a group via mosquitto_ctrl"""
    if not server_ip:
        logger.error("server_ip is required but was not provided.")
        return False, "server_ip is required"
    
    return execute_mosquitto_command(["dynsec", "removeGroupClient", group_name, username], server_ip, port, None, use_tls, cafile, certfile, keyfile, insecure)

# =====================================================
# Wrapper Functions for Views 
# (shorter names for easier imports)
# =====================================================

# Client Management
def create_client(server_ip: str, username: str, password: str, textname: str = None, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Create a client with optional textname"""
    success, message = create_client_via_mosquitto(server_ip, username, password, port, use_tls, cafile, certfile, keyfile, insecure)
    # If textname is provided and client creation succeeded, we'd need to modify it
    # However, mosquitto_ctrl doesn't have a direct way to set textname during creation
    # This would require a separate modify call which is not yet implemented in the base functions
    return success, message

def get_client(server_ip: str, username: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, dict]:
    """Get client details"""
    return get_client_via_mosquitto(server_ip, username, port, use_tls, cafile, certfile, keyfile, insecure)

def list_clients(server_ip: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, list]:
    """List all clients"""
    return get_dynsec_clients_via_mosquitto(server_ip, port, use_tls, cafile, certfile, keyfile, insecure)

def modify_client(server_ip: str, username: str, textname: str = None, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Modify client - currently only textname is supported"""
    # mosquitto_ctrl doesn't have a direct modify command for textname
    # This is a placeholder - would need to be implemented with actual mosquitto_ctrl commands
    return True, f"Client {username} modified (textname changes not yet supported)"

def delete_client(server_ip: str, username: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Delete a client"""
    return delete_client_via_mosquitto(server_ip, username, port, use_tls, cafile, certfile, keyfile, insecure)

def enable_client(server_ip: str, username: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Enable a client"""
    return enable_client_via_mosquitto(server_ip, username, port, use_tls, cafile, certfile, keyfile, insecure)

def disable_client(server_ip: str, username: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Disable a client"""
    return disable_client_via_mosquitto(server_ip, username, port, use_tls, cafile, certfile, keyfile, insecure)

def set_client_password(server_ip: str, username: str, password: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Set client password"""
    return set_client_password_via_mosquitto(server_ip, username, password, port, use_tls, cafile, certfile, keyfile, insecure)

def add_client_role(server_ip: str, username: str, role_name: str, priority: int = 1, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Add role to client"""
    return add_client_role_via_mosquitto(server_ip, username, role_name, str(priority), port, use_tls, cafile, certfile, keyfile, insecure)

def remove_client_role(server_ip: str, username: str, role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Remove role from client"""
    return remove_client_role_via_mosquitto(server_ip, username, role_name, port, use_tls, cafile, certfile, keyfile, insecure)

# Role Management
def create_role(server_ip: str, role_name: str, textname: str = None, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Create a role with optional textname"""
    success, message = create_role_via_mosquitto(server_ip, role_name, port, use_tls, cafile, certfile, keyfile, insecure)
    # textname setting would require additional implementation
    return success, message

def get_role(server_ip: str, role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, dict]:
    """Get role details"""
    return get_role_via_mosquitto(server_ip, role_name, port, use_tls, cafile, certfile, keyfile, insecure)

def list_roles(server_ip: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, list]:
    """List all roles"""
    return get_dynsec_roles_via_mosquitto(server_ip, port, use_tls, cafile, certfile, keyfile, insecure)

def modify_role(server_ip: str, role_name: str, textname: str = None, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Modify role - currently textname changes not supported"""
    return True, f"Role {role_name} modified (textname changes not yet supported)"

def delete_role(server_ip: str, role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Delete a role"""
    return delete_role_via_mosquitto(server_ip, role_name, port, use_tls, cafile, certfile, keyfile, insecure)

def add_role_acl(server_ip: str, role_name: str, acl_type: str, topic: str, allow: bool = True, priority: int = 1, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Add ACL to role"""
    permission = "allow" if allow else "deny"
    return add_role_acl_via_mosquitto(server_ip, role_name, acl_type, topic, permission, port, use_tls, cafile, certfile, keyfile, insecure)

def remove_role_acl(server_ip: str, role_name: str, acl_type: str, topic: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Remove ACL from role"""
    return remove_role_acl_via_mosquitto(server_ip, role_name, acl_type, topic, port, use_tls, cafile, certfile, keyfile, insecure)

def get_role_acls(server_ip: str, role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, list]:
    """Get ACLs for a role with improved parsing and debug logging."""
    success, role_data = get_role_via_mosquitto(server_ip, role_name, port, use_tls, cafile, certfile, keyfile, insecure)
    if success and isinstance(role_data, dict):
        acls = role_data.get('acls', [])
        if not acls:
            logger.debug("Role '%s' retrieved but had empty ACL list after parsing.", role_name)
        return True, acls
    if not success:
        logger.warning("Failed to retrieve role '%s' for ACLs", role_name)
    return success, []

# Group Management
def create_group(server_ip: str, group_name: str, textname: str = None, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Create a group with optional textname"""
    success, message = create_group_via_mosquitto(server_ip, group_name, port, use_tls, cafile, certfile, keyfile, insecure)
    # textname setting would require additional implementation
    return success, message

def get_group(server_ip: str, group_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, dict]:
    """Get group details"""
    return get_group_via_mosquitto(server_ip, group_name, port, use_tls, cafile, certfile, keyfile, insecure)

def list_groups(server_ip: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, list]:
    """List all groups"""
    return get_dynsec_groups_via_mosquitto(server_ip, port, use_tls, cafile, certfile, keyfile, insecure)

def modify_group(server_ip: str, group_name: str, textname: str = None, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Modify group - currently textname changes not supported"""
    return True, f"Group {group_name} modified (textname changes not yet supported)"

def delete_group(server_ip: str, group_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Delete a group"""
    return delete_group_via_mosquitto(server_ip, group_name, port, use_tls, cafile, certfile, keyfile, insecure)

def add_group_client(server_ip: str, group_name: str, username: str, priority: int = 1, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Add client to group"""
    return add_group_client_via_mosquitto(server_ip, group_name, username, str(priority), port, use_tls, cafile, certfile, keyfile, insecure)

def remove_group_client(server_ip: str, group_name: str, username: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Remove client from group"""
    return remove_group_client_via_mosquitto(server_ip, group_name, username, port, use_tls, cafile, certfile, keyfile, insecure)

def add_group_role(server_ip: str, group_name: str, role_name: str, priority: int = 1, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Add role to group"""
    return add_group_role_via_mosquitto(server_ip, group_name, role_name, port, use_tls, cafile, certfile, keyfile, insecure)

def remove_group_role(server_ip: str, group_name: str, role_name: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Remove role from group"""
    return remove_group_role_via_mosquitto(server_ip, group_name, role_name, port, use_tls, cafile, certfile, keyfile, insecure)

# Default ACL Management
def get_default_acl(server_ip: str, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, dict]:
    """Get default ACL settings"""
    return get_dynsec_default_acl_via_mosquitto(server_ip, port, use_tls, cafile, certfile, keyfile, insecure)

def set_default_acl(server_ip: str, acl_settings: dict, port: int = 1883, use_tls: bool = False, cafile: Optional[str] = None, certfile: Optional[str] = None, keyfile: Optional[str] = None, insecure: bool = False) -> Tuple[bool, str]:
    """Set default ACL settings - would need implementation"""
    return False, "Setting default ACL not yet implemented"
