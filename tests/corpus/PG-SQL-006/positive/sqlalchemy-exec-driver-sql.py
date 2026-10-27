# corpus: expect=PG-SQL-006
from flask import request
from sqlalchemy import create_engine

engine = create_engine("sqlite://")


def find():
    with engine.begin() as conn:
        conn.exec_driver_sql(f"SELECT * FROM t WHERE a = {request.args['a']}")
