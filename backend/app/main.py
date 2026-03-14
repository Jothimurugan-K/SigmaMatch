"""FastAPI application entry point for SigmaMatch."""

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded

from app.api.routes import router as api_router
from app.core.config import limiter

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# Allowed origins: defaults to same-origin only (empty list).
# Set ALLOWED_ORIGINS env var for deployment, e.g. "https://yourdomain.com,https://www.yourdomain.com"
_origins_env = os.environ.get("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in _origins_env.split(",") if o.strip()]

app = FastAPI(
    title="SigmaMatch",
    version="0.1.0",
    description="Upload a Sigma rule and log events to check for matches.",
)

# Attach limiter to app state so route decorators can find it
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please slow down and try again shortly."},
    )


# CORS middleware — restrict API access to trusted origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # empty = same-origin only
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# API routes
app.include_router(api_router)


@app.get("/health")
async def health():
    """Health check endpoint for load balancers and monitoring."""
    return {"status": "ok"}


# Serve static frontend
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def index():
    """Serve the single-page frontend."""
    return FileResponse(STATIC_DIR / "index.html")
