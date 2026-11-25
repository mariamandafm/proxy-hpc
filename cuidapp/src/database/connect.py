from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from settings import get_settings

engine = create_engine(
    get_settings().db_connection_url,
    # This prevents using connections that do not work anymore
    # due to the database dying after the first request
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
)
