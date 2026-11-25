import os


def get_alembic_ini():
    return os.path.join(os.path.dirname(__file__), "alembic.ini")
