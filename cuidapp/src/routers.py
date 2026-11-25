from http import HTTPStatus

from fastapi import BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import Response
from fastapi.routing import APIRouter
from sqlalchemy.orm import Session

import exceptions as exc
import handlers
from dependencies import get_db
from models import (
    BatchRegisterCuidRequest,
    BatchRegisterCuidResponse,
    CommunityUserIdentifier,
    InternalUserIdentifiers,
    MigrateCuidRequest,
)

cuidapp_router = APIRouter()
healthcheck_router = APIRouter()
test_router = APIRouter()
utils_router = APIRouter()


@cuidapp_router.post(
    "/cuid/",
    responses={
        HTTPStatus.OK: {},
        HTTPStatus.CREATED: {},
        HTTPStatus.FORBIDDEN: {},
    },
    response_model=CommunityUserIdentifier,
    status_code=status.HTTP_200_OK,
)
async def get_cuid(
    data: InternalUserIdentifiers,
    response: Response,
    background_tasks: BackgroundTasks,
    db_session: Session = Depends(get_db),
):
    try:
        cuid, is_created = handlers.get_or_create_cuid(
            db_session=db_session,
            internal_user_identifiers=data,
            background_tasks=background_tasks,
        )
        if is_created:
            response.status_code = status.HTTP_201_CREATED
    except exc.MultipleCUIDException:
        raise HTTPException(status_code=409, detail="Multiple CUIDs found")
    except exc.DatabaseError:
        raise HTTPException(status_code=500, detail="Database Error")

    return {"cuid": cuid}


@cuidapp_router.post(
    "/batch/cuids/",
    responses={
        HTTPStatus.OK: {},
        HTTPStatus.CREATED: {},
        HTTPStatus.FORBIDDEN: {},
    },
    status_code=status.HTTP_200_OK,
)
async def batch_insert_cuids(
    request_body: BatchRegisterCuidRequest,
    db_session: Session = Depends(get_db),
) -> BatchRegisterCuidResponse:
    try:
        return handlers.batch_create_cuid(db_session, request_body)
    except exc.DatabaseError:
        raise HTTPException(status_code=500, detail="Database Error")
    except exc.DuplicateCUIDException:
        raise HTTPException(status_code=400, detail="Duplicate CUID in request")


@healthcheck_router.get(
    "/healthcheck",
    status_code=status.HTTP_200_OK,
)
async def get_health(
    db_session: Session = Depends(get_db),
):
    try:
        handlers.get_health(db_session)
    except exc.DatabaseError:
        raise HTTPException(status_code=500, detail="Database Error")

    return {"status": "OK"}


@test_router.get("/test", status_code=status.HTTP_200_OK)
def get_test():
    return {"status": "OK"}


@utils_router.post(
    "/utils/cuids/",
    responses={
        HTTPStatus.OK: {},
        HTTPStatus.FORBIDDEN: {},
    },
    status_code=status.HTTP_200_OK,
)
async def get_cuids_for_iuids(
    data: InternalUserIdentifiers,
    db_session: Session = Depends(get_db),
):
    try:
        return handlers.get_cuids_for_iuids(
            db_session=db_session,
            internal_user_identifiers=data,
        )
    except exc.DatabaseError:
        raise HTTPException(status_code=500, detail="Database Error")


@utils_router.post(
    "/utils/cuids/migrate/",
    responses={
        HTTPStatus.OK: {},
        HTTPStatus.FORBIDDEN: {},
    },
    status_code=status.HTTP_200_OK,
)
async def migrate_cuid_iuids(
    request_body: MigrateCuidRequest,
    db_session: Session = Depends(get_db),
):
    try:
        return {
            "success": handlers.migrate_cuid_iuids(
                db_session,
                request_body,
            )
        }
    except exc.DatabaseError:
        raise HTTPException(status_code=500, detail="Database Error")
    except exc.CUIDNotFound:
        raise HTTPException(status_code=404, detail="CUID not found")
