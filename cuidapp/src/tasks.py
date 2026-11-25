from sqlalchemy.orm import Session

from database import operations


def add_iuids_to_cuid(
    db_session: Session,
    cuid_id: int,
    iuid_diff: set[str],
) -> None:
    operations.add_iuids_to_cuid(
        db_session,
        cuid_id,
        iuid_diff,
    )
