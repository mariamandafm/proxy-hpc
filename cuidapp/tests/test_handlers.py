from unittest.mock import MagicMock

import pytest

import handlers
from exceptions import MultipleCUIDException

from .utils import is_valid_uuid

IUID_SET_1 = [
    "89adb116fb6aa2b3638e8eb9c9d8b6d727957844@test",
    "c11bcf696a0e48c534f9707311ab2d6f2c24c54f@test",
]

IUID_SET_2 = [
    "123456@test",
    "abcddef@test",
]

IUID_SET_3 = [
    "123456@test",
    "c11bcf696a0e48c534f9707311ab2d6f2c24c54f@test",
]

NEW_IUID = "vm5qzh3fq5gavzwy6xjfb8icyrchf3ncpn7wvxb5@test"


def test_get_cuid(session):
    mock = MagicMock()

    cuid_1 = handlers.get_or_create_cuid(session, IUID_SET_1, mock)
    assert is_valid_uuid(cuid_1[0]) is True
    assert cuid_1[1]
    assert mock.add_task.call_count == 0

    mock = MagicMock()
    cuid_1_1 = handlers.get_or_create_cuid(session, [IUID_SET_1[0]], mock)
    assert is_valid_uuid(cuid_1_1[0]) is True
    assert cuid_1_1[0] == cuid_1[0]
    assert not cuid_1_1[1]
    assert mock.add_task.call_count == 0

    mock = MagicMock()
    cuid_1_2 = handlers.get_or_create_cuid(session, [IUID_SET_1[1]], mock)
    assert is_valid_uuid(cuid_1_2[0]) is True
    assert cuid_1_2[0] == cuid_1[0]
    assert mock.add_task.call_count == 0

    # Testing if new IUID is added to existing CUID
    mock = MagicMock()
    iuid_set_with_new_iuid = IUID_SET_1[:] + [NEW_IUID]
    cuid_1_3 = handlers.get_or_create_cuid(session, iuid_set_with_new_iuid, mock)
    assert cuid_1_3[0] == cuid_1_2[0]
    assert not cuid_1_3[1]
    assert mock.add_task.call_count == 1

    # Test if a different CUID is generated for a different set
    mock = MagicMock()
    cuid_2 = handlers.get_or_create_cuid(session, IUID_SET_2, mock)
    assert is_valid_uuid(cuid_2[0]) is True
    assert cuid_2[0] != cuid_1[0]
    assert mock.add_task.call_count == 0


def test_get_cuid_with_conflicting_iuids(session):
    mock = MagicMock()

    handlers.get_or_create_cuid(session, IUID_SET_1, mock)
    handlers.get_or_create_cuid(session, IUID_SET_2, mock)
    with pytest.raises(MultipleCUIDException):
        handlers.get_or_create_cuid(session, IUID_SET_3, mock)

    assert mock.add_task.call_count == 0
