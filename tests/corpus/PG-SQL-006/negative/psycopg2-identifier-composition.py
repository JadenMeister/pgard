# corpus: expect=low
from flask import request
from psycopg2 import sql


def run(cur):
    column = request.args["c"]
    cur.execute(sql.SQL("SELECT {} FROM t").format(sql.Identifier(column)))
