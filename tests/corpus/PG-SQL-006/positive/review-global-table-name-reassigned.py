# corpus: expect=PG-SQL-006
import sqlite3

from flask import request

TABLE = "users"


def switch():
    global TABLE
    TABLE = request.args["table"]


def count():
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT COUNT(*) FROM {TABLE}")
