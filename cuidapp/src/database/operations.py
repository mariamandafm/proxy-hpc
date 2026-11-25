from typing import Iterable, List

from sqlalchemy.orm import Session

from database import models


def get_cuid(db_session: Session, cuid: str) -> models.CommunityUserIdentifier:
    query = db_session.query(
        models.CommunityUserIdentifier,
    ).filter(models.CommunityUserIdentifier.cuid == cuid)
    return query.one_or_none()


def move_cuid_reference(
    db_session: Session,
    from_cuid_id: int,
    to_cuid_id: int,
):
    (
        db_session.query(models.InternalUserIdentifier)
        .filter(models.InternalUserIdentifier.cuid_id == from_cuid_id)
        .update(
            {
                models.InternalUserIdentifier.cuid_id: to_cuid_id,
            },
            synchronize_session=False,
        )
    )
    db_session.commit()


def get_cuid_by_iuids(
    db_session: Session,
    internal_user_identifiers: List[str],
) -> List:
    return [
        row
        for row in (
            db_session.query(
                models.CommunityUserIdentifier.id,
                models.CommunityUserIdentifier.cuid,
                models.InternalUserIdentifier.iuid,
            )
            .outerjoin(models.InternalUserIdentifier)
            .filter(models.InternalUserIdentifier.iuid.in_(internal_user_identifiers))
        )
    ]


def add_iuids_to_cuid(
    db_session: Session,
    cuid_id: int,
    internal_user_identifiers: Iterable[str],
) -> None:
    iuids = [
        models.InternalUserIdentifier(iuid=iuid, cuid_id=cuid_id)
        for iuid in internal_user_identifiers
    ]
    db_session.bulk_save_objects(iuids)
    db_session.commit()


def create_cuid(
    db_session: Session,
    internal_user_identifiers: List[str],
    cuid: str,
) -> str:
    cuid_entry = models.CommunityUserIdentifier(cuid=cuid)
    iuids = [
        models.InternalUserIdentifier(iuid=iuid) for iuid in internal_user_identifiers
    ]
    cuid_entry.internal_user_identifiers = iuids
    db_session.add(cuid_entry)
    db_session.commit()
    return cuid_entry.cuid


def db_conn_health(db_session: Session) -> str:
    result = db_session.query(1).all()
    return result
