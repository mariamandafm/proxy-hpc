import importlib.metadata


def _parse_version():
    return importlib.metadata.version("coreaai_proxy_plugins")


version = _parse_version()
