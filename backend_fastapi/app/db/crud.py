from __future__ import annotations

import uuid
from datetime import datetime, timezone
from sqlalchemy import select, update, insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import models


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def create_tenant(session: AsyncSession, *, org_name: str, org_slug: str, workspace_name: str, workspace_slug: str, user_name: str, email: str, password_hash: str):
    org = models.Organization(name=org_name, slug=org_slug)
    user = models.User(name=user_name, email=email.lower(), password_hash=password_hash)
    workspace = models.Workspace(name=workspace_name, slug=workspace_slug, organization=org)
    session.add_all([org, user, workspace])
    await session.flush()  # assign IDs
    membership = models.Membership(workspace_id=workspace.id, user_id=user.id, role="owner")
    session.add(membership)
    await session.commit()
    return org, workspace, user


async def find_user_by_email(session: AsyncSession, email: str) -> models.User | None:
    q = await session.execute(select(models.User).where(models.User.email == email.lower()))
    return q.scalar_one_or_none()


async def workspaces_for_user(session: AsyncSession, user_id: uuid.UUID):
    q = await session.execute(
        select(models.Workspace, models.Membership.role, models.Organization.name, models.Organization.plan)
        .join(models.Membership, models.Membership.workspace_id == models.Workspace.id)
        .join(models.Organization, models.Organization.id == models.Workspace.organization_id)
        .where(models.Membership.user_id == user_id)
    )
    results = []
    for ws, role, org_name, plan in q.all():
        results.append({
            "id": str(ws.id),
            "name": ws.name,
            "slug": ws.slug,
            "organization_id": str(ws.organization_id),
            "organization_name": org_name,
            "plan": plan,
            "role": role,
        })
    return results


async def membership_for_user(session: AsyncSession, user_id: uuid.UUID, workspace_id: uuid.UUID) -> models.Membership | None:
    q = await session.execute(select(models.Membership).where(models.Membership.user_id == user_id, models.Membership.workspace_id == workspace_id))
    return q.scalar_one_or_none()


async def create_api_key(session: AsyncSession, *, workspace_id: uuid.UUID, name: str, key_prefix: str, key_hash: str, role: str, expires_at: datetime | None):
    key = models.ApiKey(
        workspace_id=workspace_id,
        name=name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        role=role,
        expires_at=expires_at,
    )
    session.add(key)
    await session.commit()
    return key


async def auth_api_key(session: AsyncSession, key_hash: str) -> models.ApiKey | None:
    now = utcnow()
    q = await session.execute(
        select(models.ApiKey).where(
            models.ApiKey.key_hash == key_hash,
            models.ApiKey.revoked_at.is_(None),
        )
    )
    key = q.scalar_one_or_none()
    if not key:
        return None
    # Check expiry
    if key.expires_at is not None and key.expires_at < now:
        return None
    key.last_used_at = now
    await session.commit()
    return key


async def increment_usage(session: AsyncSession, *, workspace_id: uuid.UUID, period: str, metric: str, amount: int = 1) -> int:
    # upsert
    await session.execute(
        insert(models.UsageCounter)
        .values(workspace_id=workspace_id, period=period, metric=metric, value=amount)
        .on_conflict_do_update(
            index_elements=[models.UsageCounter.workspace_id, models.UsageCounter.period, models.UsageCounter.metric],
            set_={"value": models.UsageCounter.value + amount},
        )
    )
    await session.commit()
    q = await session.execute(select(models.UsageCounter.value).where(models.UsageCounter.workspace_id == workspace_id, models.UsageCounter.period == period, models.UsageCounter.metric == metric))
    return int(q.scalar_one())


async def get_usage(session: AsyncSession, *, workspace_id: uuid.UUID, period: str) -> dict[str, int]:
    q = await session.execute(select(models.UsageCounter.metric, models.UsageCounter.value).where(models.UsageCounter.workspace_id == workspace_id, models.UsageCounter.period == period))
    return {metric: int(value) for metric, value in q.all()}


async def find_user_by_id(session: AsyncSession, user_id: uuid.UUID) -> models.User | None:
    q = await session.execute(select(models.User).where(models.User.id == user_id))
    return q.scalar_one_or_none()


async def get_workspace(session: AsyncSession, workspace_id: uuid.UUID) -> models.Workspace | None:
    q = await session.execute(select(models.Workspace).where(models.Workspace.id == workspace_id))
    return q.scalar_one_or_none()


async def create_reset_token(session: AsyncSession, *, user_id: uuid.UUID, token_hash: str, expires_at: datetime):
    from app.db.models import ResetToken
    rt = ResetToken(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
    session.add(rt)
    await session.commit()
    return rt


async def consume_reset_token(session: AsyncSession, token_hash: str, new_password_hash: str) -> bool:
    from app.db.models import ResetToken, User
    now = utcnow()
    q = await session.execute(
        select(ResetToken).where(
            ResetToken.token_hash == token_hash,
            ResetToken.consumed_at.is_(None),
            ResetToken.expires_at > now,
        )
    )
    rt = q.scalar_one_or_none()
    if not rt:
        return False
    rt.consumed_at = now
    q2 = await session.execute(select(User).where(User.id == rt.user_id))
    user = q2.scalar_one_or_none()
    if user:
        user.password_hash = new_password_hash
    await session.commit()
    return True


# ---- Product CRUD ----

async def list_workspace_items(session: AsyncSession, model_class, workspace_id: uuid.UUID):
    q = await session.execute(select(model_class).where(model_class.workspace_id == workspace_id))
    return q.scalars().all()


async def get_item_by_id(session: AsyncSession, model_class, item_id: uuid.UUID):
    q = await session.execute(select(model_class).where(model_class.id == item_id))
    return q.scalar_one_or_none()


async def add_item(session: AsyncSession, item):
    session.add(item)
    await session.commit()
    return item


async def update_item(session: AsyncSession, item, **kwargs):
    for k, v in kwargs.items():
        setattr(item, k, v)
    await session.commit()
    return item


# ---- Audit ----

async def append_audit(session: AsyncSession, *, workspace_id: uuid.UUID, actor_id: str, action: str, resource_type: str, resource_id: str, metadata: dict | None = None, previous_hash: str = "GENESIS"):
    from app.core.audit import create_audit_event
    event = create_audit_event(
        workspace_id=str(workspace_id), actor_id=actor_id, action=action,
        resource_type=resource_type, resource_id=resource_id, metadata=metadata or {},
        previous_hash=previous_hash,
    )
    db_event = models.AuditEvent(
        workspace_id=workspace_id, actor_id=actor_id, action=action,
        resource_type=resource_type, resource_id=resource_id, audit_metadata=event["metadata"],
        previous_hash=event["previousHash"], hash=event["hash"],
    )
    session.add(db_event)
    await session.commit()
    return event


async def audit_events(session: AsyncSession, workspace_id: uuid.UUID):
    q = await session.execute(
        select(models.AuditEvent).where(models.AuditEvent.workspace_id == workspace_id).order_by(models.AuditEvent.timestamp)
    )
    return q.scalars().all()


# ---- Webhooks ----

async def add_webhook(session: AsyncSession, *, workspace_id: uuid.UUID, url: str, secret: str, events: list):
    wh = models.WebhookEndpoint(workspace_id=workspace_id, url=url, secret=secret, events=events)
    session.add(wh)
    await session.commit()
    return wh


# ---- Invitations ----

async def create_invitation(session: AsyncSession, *, workspace_id: uuid.UUID, email: str, role: str, token_hash: str, expires_at: datetime, invited_by: str):
    from app.db.models import Invitation
    inv = Invitation(workspace_id=workspace_id, email=email.lower(), role=role, token_hash=token_hash, expires_at=expires_at, invited_by=invited_by)
    session.add(inv)
    await session.commit()
    return inv


async def accept_invitation(session: AsyncSession, token_hash: str, user_id: uuid.UUID) -> dict | None:
    from app.db.models import Invitation, Membership
    now = utcnow()
    q = await session.execute(
        select(Invitation).where(
            Invitation.token_hash == token_hash,
            Invitation.accepted_at.is_(None),
            Invitation.expires_at > now,
        )
    )
    inv = q.scalar_one_or_none()
    if not inv:
        return None
    inv.accepted_at = now
    membership = Membership(workspace_id=inv.workspace_id, user_id=user_id, role=inv.role)
    session.add(membership)
    await session.commit()
    return {"workspace_id": str(inv.workspace_id), "role": inv.role}


async def list_invitations(session: AsyncSession, workspace_id: uuid.UUID):
    from app.db.models import Invitation
    q = await session.execute(
        select(Invitation).where(Invitation.workspace_id == workspace_id, Invitation.accepted_at.is_(None))
    )
    return q.scalars().all()


async def list_members(session: AsyncSession, workspace_id: uuid.UUID):
    q = await session.execute(
        select(models.Membership, models.User).join(models.User, models.Membership.user_id == models.User.id).where(models.Membership.workspace_id == workspace_id)
    )
    results = []
    for m, u in q.all():
        results.append({"id": str(m.id), "user_id": str(u.id), "email": u.email, "name": u.name, "role": m.role})
    return results
