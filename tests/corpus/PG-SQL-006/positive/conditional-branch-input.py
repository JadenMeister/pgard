# corpus: expect=PG-SQL-006
import sqlite3

from flask import request


def run(flag):
    cur = sqlite3.connect("x").cursor()
    if flag:
        where = "a = '" + request.args["a"] + "'"
    else:
        where = "a = 1"
    cur.execute("SELECT * FROM t WHERE " + where)
