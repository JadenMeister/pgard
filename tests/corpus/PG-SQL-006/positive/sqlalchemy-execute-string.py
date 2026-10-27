# corpus: expect=PG-SQL-006
from flask import request
from sqlalchemy import create_engine

engine = create_engine("sqlite://")


def find():
    with engine.connect() as conn:
        return conn.execute("SELECT * FROM users WHERE name = '%s'" % request.args["name"])
