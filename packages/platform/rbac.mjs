export const ROLE_PERMISSIONS = {
  owner: ['*'],
  admin: ['agents:*','policies:*','permits:*','approvals:*','credentials:*','receipts:read','incidents:*','members:*','billing:read'],
  policy_author: ['agents:read','policies:*','permits:*','approvals:read','receipts:read'],
  approver: ['agents:read','policies:read','permits:read','approvals:*','receipts:read'],
  auditor: ['agents:read','policies:read','permits:read','approvals:read','receipts:read','audit:read','incidents:read'],
  viewer: ['agents:read','policies:read','permits:read','receipts:read']
};

export function can(role, permission) {
  const allowed = ROLE_PERMISSIONS[role] || [];
  if (allowed.includes('*') || allowed.includes(permission)) return true;
  const [resource] = permission.split(':');
  return allowed.includes(`${resource}:*`);
}

export function requirePermission(context, permission) {
  if (!context?.userId || !context?.workspaceId) throw Object.assign(new Error('Authentication required'), { status: 401 });
  if (!can(context.role, permission)) throw Object.assign(new Error(`Missing permission: ${permission}`), { status: 403 });
  return context;
}
