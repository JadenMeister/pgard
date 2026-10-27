# corpus: expect=PG-SQL-006
from flask import request
import sqlalchemy as sa


def find(session):
    return session.execute(sa.text("SELECT * FROM users WHERE id = " + request.args["id"]))
