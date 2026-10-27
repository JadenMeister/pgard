# corpus: expect=PG-SQL-006
from flask import request
from sqlalchemy import text


def find(session):
    return session.execute(text(f"SELECT * FROM users WHERE name = '{request.args['name']}'"))
