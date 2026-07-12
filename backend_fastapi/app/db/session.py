from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode


def make_engine(database_url: str):
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    if database_url.startswith("postgresql://") and "+asyncpg" not in database_url:
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    # Normalize SSL params for asyncpg (it uses 'ssl', not 'sslmode')
    if "+asyncpg" in database_url:
        parsed = urlparse(database_url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if "sslmode" in query:
            query["ssl"] = query.pop("sslmode")
        database_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    return create_async_engine(database_url, pool_pre_ping=True)


def make_session_factory(engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
