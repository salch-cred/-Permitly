from pydantic import BaseModel, EmailStr, Field
from typing import Any


class RegisterRequest(BaseModel):
    organizationName: str
    organizationSlug: str
    workspaceName: str = "Production"
    workspaceSlug: str = "production"
    name: str
    email: EmailStr
    password: str


class RegisterResponse(BaseModel):
    organizationId: str
    workspaceId: str
    userId: str
    token: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    workspaceId: str | None = None


class LoginResponse(BaseModel):
    token: str
    user: dict[str, Any]
    workspace: dict[str, Any]


class ApiKeyCreateRequest(BaseModel):
    name: str = "API key"
    role: str = "admin"
    environment: str = "test"  # test|live
    expiresAt: str | None = None


class ApiKeyCreateResponse(BaseModel):
    key: dict[str, Any]
