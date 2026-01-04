"""Main FastAPI application"""
from fastapi import FastAPI, Request, Depends, Form, Response
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.config import settings
from app.api import api_router
from app.auth import verify_credentials
import app.mosquitto_ctrl as mosquitto_ctrl

# Create FastAPI app
app = FastAPI(
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Setup templates
templates = Jinja2Templates(directory="app/templates")

# Include API routes
app.include_router(api_router, prefix="/api")


@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to web UI login"""
    return RedirectResponse(url="/ui/login")


@app.get("/ui/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    """Display login page"""
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/ui/login", include_in_schema=False)
async def login_submit(response: Response, username: str = Form(...), password: str = Form(...)):
    """Handle login form submission"""
    import secrets
    correct_username = settings.API_USERNAME
    correct_password = settings.API_PASSWORD
    
    is_correct_username = secrets.compare_digest(username.encode("utf8"), correct_username.encode("utf8"))
    is_correct_password = secrets.compare_digest(password.encode("utf8"), correct_password.encode("utf8"))
    
    if is_correct_username and is_correct_password:
        response = RedirectResponse(url="/ui/dashboard", status_code=303)
        # Set a simple cookie for session (in production, use proper session management)
        import base64
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        response.set_cookie(key="auth_token", value=token, httponly=True)
        return response
    else:
        return RedirectResponse(url="/ui/login?error=1", status_code=303)


@app.get("/ui/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_page(request: Request):
    """Display main dashboard"""
    # Check authentication via cookie
    auth_token = request.cookies.get("auth_token")
    if not auth_token:
        return RedirectResponse(url="/ui/login")
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "api_base": "/api",
        "auth_token": auth_token
    })


@app.get("/ui/logout", include_in_schema=False)
async def logout():
    """Logout and clear session"""
    response = RedirectResponse(url="/ui/login")
    response.delete_cookie("auth_token")
    return response


@app.get("/health")
async def health_check():
    """
    Health check endpoint.
    
    Verifies that the API is running and mosquitto_ctrl is available.
    """
    ctrl_available = mosquitto_ctrl.check_mosquitto_ctrl_available()
    
    return {
        "status": "healthy" if ctrl_available else "degraded",
        "mosquitto_ctrl_available": ctrl_available,
        "version": settings.APP_VERSION,
        "mosquitto_host": settings.DEFAULT_MOSQUITTO_HOST,
        "mosquitto_port": settings.DEFAULT_MOSQUITTO_PORT,
    }


@app.get("/api")
async def api_info():
    """
    API information endpoint.
    
    Returns basic information about the API and available endpoints.
    """
    return {
        "name": settings.APP_TITLE,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
        "endpoints": {
            "clients": "/api/clients",
            "roles": "/api/roles",
            "groups": "/api/groups",
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
