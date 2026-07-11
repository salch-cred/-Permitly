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
