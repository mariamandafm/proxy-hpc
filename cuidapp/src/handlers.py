import uuid
from typing import Tuple

from fastapi import BackgroundTasks
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from database import operations
from exceptions import (
    CUIDNotFound,
    DatabaseError,
    DuplicateCUIDException,
    MultipleCUIDException,
)
from models import (
    BatchRegisterCuidRequest,
    BatchRegisterCuidResponse,
    InternalUserIdentifiers,
    MigrateCuidRequest,
)
from tasks import add_iuids_to_cuid


def get_cuid(
    db_session: Session,
    internal_user_identifiers: InternalUserIdentifiers,
):
    try:
        return operations.get_cuid_by_iuids(db_session, internal_user_identifiers)
    except OperationalError:
        raise DatabaseError


def _generate_cuid_map(get_cuid_result):
    cuid_map = {}

    for cuid_id, cuid, iuid in get_cuid_result:
        cuid_map.setdefault((cuid_id, cuid), []).append(iuid)

    return cuid_map


def _extract_iuid_diff(cuid_map, internal_user_identifiers):
    key = list(cuid_map.keys())[0]
    cuid_id, cuid = key
    iuid_diff = set(internal_user_identifiers) - set(cuid_map[key])
    return cuid, cuid_id, iuid_diff


def _extract_multiple_cuids(cuid_map):
    keys = list(cuid_map.keys())
    return [x[1] for x in keys]


def migrate_cuid_iuids(
    db_session: Session,
    request: MigrateCuidRequest,
) -> bool:
    source_cuid_record = operations.get_cuid(db_session, request.source_cuid)
    target_cuid_record = operations.get_cuid(db_session, request.target_cuid)
    if source_cuid_record is None:
        raise CUIDNotFound
    if target_cuid_record is None:
        raise CUIDNotFound

    operations.move_cuid_reference(
        db_session,
        from_cuid_id=source_cuid_record.id,
        to_cuid_id=target_cuid_record.id,
    )

    return True


def get_cuids_for_iuids(
    db_session: Session,
    internal_user_identifiers: InternalUserIdentifiers,
) -> dict[str, list[str]]:
    get_cuid_result = operations.get_cuid_by_iuids(
        db_session,
        internal_user_identifiers,
    )
    cuid_map = _generate_cuid_map(get_cuid_result)
    cuid_to_iuid_map = {}
    existing_iuids = []
    for key, value in cuid_map.items():
        cuid_to_iuid_map[key[1]] = value
        existing_iuids.extend(value)

    cuid_to_iuid_map["__NOT_REGISTERED"] = set(internal_user_identifiers) - set(
        existing_iuids
    )
    return cuid_to_iuid_map


def batch_create_cuid(
    db_session: Session,
    request_body: BatchRegisterCuidRequest,
) -> BatchRegisterCuidResponse:
    results = []

    cuids = [r.cuid for r in request_body.records]
    if len(set(cuids)) < len(cuids):
        raise DuplicateCUIDException

    for record in request_body.records:
        current = {
            **record.model_dump(),
        }
        get_cuid_result = operations.get_cuid_by_iuids(db_session, record.iuids)
        cuid_map = _generate_cuid_map(get_cuid_result)

        if len(cuid_map) > 1:
            # The iuid set is mapped to multiple cuids, that's bad
            current["success"] = False
            current["message"] = (
                f"Multiple CUIDs found for IUID set: "
                f"{_extract_multiple_cuids(cuid_map)}"
            )
        elif len(cuid_map) == 1:
            # The iuid set is mapped to a single cuid, merge the iuid list
            cuid, cuid_id, iuid_diff = _extract_iuid_diff(
                cuid_map,
                record.iuids,
            )

            if cuid == record.cuid:
                operations.add_iuids_to_cuid(
                    db_session,
                    cuid_id,
                    iuid_diff,
                )
                current["success"] = True
                current["message"] = "CUID exists, merged with existing IUID list"
            else:
                current["success"] = False
                current["message"] = f"IUID provided mapped to different cuid: {cuid}"
        else:
            # Else, the cuid is not yet used, create the record
            operations.create_cuid(
                db_session,
                record.iuids,
                record.cuid,
            )
            current["success"] = True
            current["message"] = "CUID + IUIDs created"

        results.append(current)

    return BatchRegisterCuidResponse(
        results=results,
    )


def get_or_create_cuid(
    db_session: Session,
    internal_user_identifiers: InternalUserIdentifiers,
    background_tasks: BackgroundTasks,
) -> Tuple[str, bool]:
    """
    @return: Tuple of retrieved (or created) CUID,
    and a boolean signifying if the CUID is newly created
    """
    result = get_cuid(db_session, internal_user_identifiers)
    cuid_map = _generate_cuid_map(result)

    if len(cuid_map) > 1:
        raise MultipleCUIDException

    if len(cuid_map) == 1:
        cuid, cuid_id, iuid_diff = _extract_iuid_diff(
            cuid_map,
            internal_user_identifiers,
        )
        if iuid_diff:
            background_tasks.add_task(
                add_iuids_to_cuid,
                db_session,
                cuid_id,
                iuid_diff,
            )

        return cuid, False

    try:
        cuid = str(uuid.uuid4())
        return (
            operations.create_cuid(
                db_session,
                internal_user_identifiers,
                cuid,
            ),
            True,
        )
    except OperationalError:
        raise DatabaseError


def get_health(db_session: Session) -> str:
    try:
        return operations.db_conn_health(db_session)
    except OperationalError:
        raise DatabaseError
