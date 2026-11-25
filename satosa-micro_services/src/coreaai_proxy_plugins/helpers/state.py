from satosa.internal import InternalData


KEY_INTERNAL_DATA = "intdata"


def store(state, key: str, data):
    state[key] = data


def restore(state, key: str, default=None):
    data = state.pop(key, default)
    return data


def store_internal_data(state, data):
    store(state, KEY_INTERNAL_DATA, data)


def restore_internal_data(state):
    value = restore(state, KEY_INTERNAL_DATA, default={})
    data = InternalData.from_dict(value)
    data.metadata = value.get("metadata", {})
    return data
