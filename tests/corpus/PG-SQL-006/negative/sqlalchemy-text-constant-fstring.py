# corpus: expect=none
from flask import request
from sqlalchemy import text

TABLE = "users"


def find(session):
    return session.execute(text(f"SELECT * FROM {TABLE} WHERE name = :n"), {"n": request.args["name"]})
