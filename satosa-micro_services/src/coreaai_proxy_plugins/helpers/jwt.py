import uuid
from datetime import datetime, timezone, timedelta
from typing import Literal, get_args, Optional, Any, Mapping

import jwt

SupportedAlgorithm = Literal[
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES521", "ES512"
]
all_supported_algorithms: set[SupportedAlgorithm] = set(get_args(SupportedAlgorithm))


def validate_signing_keys(value: Any) -> jwt.PyJWKSet:
    jwks = jwt.PyJWKSet.from_dict(value)
    has_valid_signing_key = any(
        jwk
        for jwk in jwks.keys
        if jwk.algorithm_name in all_supported_algorithms
        and is_valid_signing_key(jwk.key, jwk.algorithm_name)
    )
    if not has_valid_signing_key:
        raise ValueError("no valid signing key found")
    return jwks


def resolve_signing_key(jwks: jwt.PyJWKSet, algorithms=None) -> Optional[jwt.PyJWK]:
    if algorithms is None:
        algorithms = all_supported_algorithms
    for jwk in jwks.keys:
        if jwk.algorithm_name in algorithms:
            if is_valid_signing_key(jwk.key, jwk.algorithm_name):
                return jwk
    return None


def is_valid_signing_key(key: Any, algorithm: SupportedAlgorithm = "RS256"):
    try:
        # Try to encode a sample payload using the provided key
        jwt.encode({"test": "payload"}, key, algorithm)
        return True
    except jwt.InvalidKeyError as err:
        return False


def sign_token(
    jwks: jwt.PyJWKSet,
    sub: str,
    payload: Optional[Mapping[str, Any]] = None,
    max_age_seconds: int = 5 * 60,
    algorithms=None,
) -> str:
    if algorithms is None:
        algorithms = all_supported_algorithms
    jwk = resolve_signing_key(jwks, algorithms)
    assert jwk is not None, "no valid JWK found"
    _payload = {}
    if payload is not None:
        _payload.update(payload)

    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=max_age_seconds)
    _payload.update(
        {
            "sub": sub,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": str(uuid.uuid4()),
        }
    )

    token = jwt.encode(
        payload=_payload,
        key=jwk.key,
        algorithm=jwk.algorithm_name,
        headers={"kid": jwk.key_id},
    )
    return token
