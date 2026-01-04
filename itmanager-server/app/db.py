from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from .settings import settings


def _sqlalchemy_url() -> str:
    # SQLAlchemy pyodbc URL. Driver needs '+' for spaces.
    driver = settings.mssql_driver.replace(" ", "+")
    trust = "yes" if settings.mssql_trust_cert else "no"
    return (
        f"mssql+pyodbc://{settings.mssql_user}:{settings.mssql_password}"
        f"@{settings.mssql_host}/{settings.mssql_db}"
        f"?driver={driver}&Encrypt=yes&TrustServerCertificate={trust}"
    )


engine = create_engine(_sqlalchemy_url(), pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass
