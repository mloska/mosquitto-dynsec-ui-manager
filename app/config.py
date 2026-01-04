"""Configuration management for Mosquitto DynSec UI Manager"""
import os
from typing import Optional


class Settings:
    """Application settings loaded from environment variables"""
    
    # API Authentication
    API_USERNAME: str = os.getenv("API_USERNAME", "admin")
    API_PASSWORD: str = os.getenv("API_PASSWORD", "admin")
    
    # Default Mosquitto Connection (can be overridden per request)
    DEFAULT_MOSQUITTO_HOST: str = os.getenv("MOSQUITTO_HOST", "mosquitto")
    DEFAULT_MOSQUITTO_PORT: int = int(os.getenv("MOSQUITTO_PORT", "1883"))
    
    # Mosquitto Admin Credentials (for mosquitto_ctrl commands)
    MOSQUITTO_ADMIN_USERNAME: str = os.getenv("MOSQUITTO_ADMIN_USERNAME", "admin")
    MOSQUITTO_ADMIN_PASSWORD: str = os.getenv("MOSQUITTO_ADMIN_PASSWORD", "admin")
    
    # Application Settings
    APP_TITLE: str = "Mosquitto Dynamic Security Manager"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = """
    REST API for managing Mosquitto MQTT broker users, roles, groups, and ACLs.
    
    This application provides a clean interface to Mosquitto's Dynamic Security plugin,
    allowing you to manage MQTT clients, roles, groups, and access control lists (ACLs).
    
    ## Features
    - **Client Management**: Create, list, enable/disable, and delete MQTT clients
    - **Role Management**: Define roles with custom ACLs
    - **Group Management**: Organize clients into groups with assigned roles
    - **ACL Control**: Fine-grained publish/subscribe permissions
    - **Multi-Server Support**: Manage multiple Mosquitto instances
    
    ## Authentication
    This API uses HTTP Basic Authentication. Default credentials:
    - Username: admin
    - Password: admin
    
    **Important**: Change these credentials in production using environment variables!
    """
    
    @classmethod
    def get_mosquitto_admin_username(cls) -> str:
        """Get Mosquitto admin username for mosquitto_ctrl"""
        return cls.MOSQUITTO_ADMIN_USERNAME
    
    @classmethod
    def get_mosquitto_admin_password(cls) -> str:
        """Get Mosquitto admin password for mosquitto_ctrl"""
        return cls.MOSQUITTO_ADMIN_PASSWORD


settings = Settings()
