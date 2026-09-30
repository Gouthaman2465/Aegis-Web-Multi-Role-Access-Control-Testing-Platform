"""FastAPI platform entrypoint, middleware, routers, and global exception handlers."""

import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi import APIRouter

from app.api.admin import router as admin_router
from app.api.auth import router as auth_router
from app.api.findings import router as findings_router
from app.api.health import router as health_router
from app.api.scans import router as scans_router
from app.api.targets import router as targets_router
from app.config import get_settings

logger = logging.getLogger("aegis_backend")

settings = get_settings()

app = FastAPI(
    title="Aegis-Web API",
    description="Access-Control Testing Platform Backend",
    version="1.0.0",
)

# 1. CORS Middleware (explicit origin allowlist, never wildcard '*')
origins = [orig.strip() for orig in settings.CORS_ORIGINS.split(",") if orig.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 2. Hardened Security Headers Middleware (Nosniff, No-Store, No-Referrer)
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# 3. Global Exception Handler (Suppress stack traces to clients)
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        return await http_exception_handler(request, exc)

    logger.exception(f"Unhandled server error at {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
        },
    )


# 4. API v1 Routing
api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(health_router)
api_v1.include_router(auth_router)
api_v1.include_router(targets_router)
api_v1.include_router(scans_router)
api_v1.include_router(findings_router)
api_v1.include_router(admin_router)

app.include_router(api_v1)
