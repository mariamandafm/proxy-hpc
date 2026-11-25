from base64 import urlsafe_b64encode as encode_b64urlsafe
from base64 import urlsafe_b64decode as decode_b64urlsafe

from json import dumps as serialize_to_json
from json import loads as deserialize_from_json

from coreaai_proxy_plugins.helpers.errors import Error as _Error


class Error(_Error):
    ...


def serialize_payload(payload: dict) -> str:
    serialized = serialize_to_json(payload, separators=(", ", ":"))
    encoded = serialized.encode("utf-8")
    b64encoded = encode_b64urlsafe(encoded)
    encoded = b64encoded.decode("utf-8")
    return encoded


def deserialize_payload(serialized_payload: str) -> dict:
    try:
        b64decoded = decode_b64urlsafe(serialized_payload)
        decoded = b64decoded.decode("utf-8")
        unserialized = deserialize_from_json(decoded)
    except Exception as e:
        error_context = {
            "message": "Cannot decode data to expected format",
            "payload": serialized_payload,
            "exception": str(e),
        }
        raise Error(error_context)
    else:
        return unserialized
