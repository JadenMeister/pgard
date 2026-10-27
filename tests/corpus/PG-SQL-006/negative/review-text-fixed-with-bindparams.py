# corpus: expect=none
from flask import request
from sqlalchemy import text


def find(session):
    stmt = text("SELECT * FROM users WHERE name = :n").bindparams(n=request.args["name"])
    return session.execute(stmt)
