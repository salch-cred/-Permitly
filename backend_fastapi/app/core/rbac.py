ROLE_PERMISSIONS: dict[str, list[str]] = {
    "owner": ["*"],
    "admin": [
        "agents:*",
        "policies:*",
        "permits:*",
        "approvals:*",
        "credentials:*",
        "receipts:read",
        "incidents:*",
        "members:*",
        "billing:read",
        "audit:read",
    ],
    "policy_author": ["agents:read", "policies:*", "permits:*", "approvals:read", "receipts:read"],
    "approver": ["agents:read", "policies:read", "permits:read", "approvals:*", "receipts:read"],
    "auditor": ["agents:read", "policies:read", "permits:read", "approvals:read", "receipts:read", "audit:read", "incidents:read"],
    "viewer": ["agents:read", "policies:read", "permits:read", "receipts:read"],
}


def can(role: str, permission: str) -> bool:
    allowed = ROLE_PERMISSIONS.get(role, [])
    if "*" in allowed or permission in allowed:
        return True
    resource = permission.split(":", 1)[0]
    return f"{resource}:*" in allowed


def require_permission(role: str, permission: str) -> None:
    if not can(role, permission):
        raise PermissionError(f"Missing permission: {permission}")
