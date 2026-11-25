from typing import NewType

ClientId = NewType("ClientId", str)

# TODO: Add fields on ClientInfo for proper typing
ClientInfo = NewType("ClientInfo", dict)

ClientSource = dict[
    ClientId, ClientInfo
]  # ClientSource is expected to behave like a dictionary

# Singleton to represent values that should have been "undefined", but not necessarily None
Undefined = object()
