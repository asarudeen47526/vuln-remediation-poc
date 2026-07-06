import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/vulndb")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,       # background threads + uvicorn workers
    max_overflow=20,    # burst headroom
    pool_timeout=60,    # wait up to 60s before raising TimeoutError
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
