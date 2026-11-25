class CUIDException(Exception):
    pass


class CUIDNotFound(Exception):
    pass


class MultipleCUIDException(CUIDException):
    def __str__(self) -> str:
        return "Multiple CUIDs found"


class DuplicateCUIDException(CUIDException):
    def __str__(self) -> str:
        return "Duplicates CUID in request"


class DatabaseError(Exception):
    def __str__(self) -> str:
        return "Database Error"
