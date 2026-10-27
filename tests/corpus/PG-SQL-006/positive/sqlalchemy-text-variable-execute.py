# corpus: expect=PG-SQL-006
from flask import request
from sqlalchemy import text


def find(session):
    stmt = text("SELECT * FROM users WHERE name = '" + request.args["name"] + "'")
    return session.execute(stmt)
