# corpus: expect=none
from flask import request
from sqlalchemy import text


def find(session):
    return session.execute(text("SELECT * FROM users WHERE name = :n"), {"n": request.args["name"]})
