"""Authentication utilities"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
from app.config import settings

security = HTTPBasic()


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    """
    Verify HTTP Basic Authentication credentials.
    
    Returns the username if authentication succeeds.
    Raises HTTPException if credentials are invalid.
    """
    correct_username = settings.API_USERNAME
    correct_password = settings.API_PASSWORD
    
    is_correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"),
        correct_username.encode("utf8")
    )
    is_correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"),
        correct_password.encode("utf8")
    )
    
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return credentials.username
