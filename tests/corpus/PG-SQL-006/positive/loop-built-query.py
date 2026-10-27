# corpus: expect=PG-SQL-006
import sqlite3

from flask import request


def run():
    cur = sqlite3.connect("x").cursor()
    query = "SELECT * FROM t WHERE 1=1"
    for key in request.args:
        query += " AND " + key + " = 1"
    cur.execute(query)
