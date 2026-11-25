from fastapi import FastAPI, HTTPException, status
from fastapi.param_functions import Security
from fastapi.security.api_key import APIKeyHeader, APIKeyQuery

from routers import cuidapp_router, healthcheck_router, test_router, utils_router
from settings import get_settings

API_KEY_NAME = "access_token"
API_KEYS = get_settings().api_keys


def api_key_validator(
    api_key_query: str = Security(APIKeyQuery(name=API_KEY_NAME, auto_error=False)),
    api_key_header: str = Security(APIKeyHeader(name=API_KEY_NAME, auto_error=False)),
):
    if api_key_query in API_KEYS:
        return api_key_query
    elif api_key_header in API_KEYS:
        return api_key_header
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid credentials"
        )


app = FastAPI(title="CUID APP")

app.include_router(
    cuidapp_router,
    dependencies=[Security(api_key_validator)],
    tags=["operations"],
)
app.include_router(healthcheck_router, tags=["healthcheck"])
app.include_router(test_router, tags=["test"])

if get_settings().enable_util_endpoints:
    app.include_router(
        utils_router,
        dependencies=[Security(api_key_validator)],
        tags=["utils"],
    )
