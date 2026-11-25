from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class InternalUserIdentifier(Base):
    __tablename__ = "IUID"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True,
    )
    iuid = Column(
        String,
        index=True,
        unique=True,
    )
    cuid_id = Column(
        Integer,
        ForeignKey("CUID.id"),
    )
    community_user_identifier = relationship(
        "CommunityUserIdentifier", back_populates="internal_user_identifiers"
    )


class CommunityUserIdentifier(Base):
    __tablename__ = "CUID"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True,
    )
    cuid = Column(
        String,
        index=True,
        unique=True,
    )
    internal_user_identifiers = relationship(
        "InternalUserIdentifier",
        back_populates="community_user_identifier",
    )
