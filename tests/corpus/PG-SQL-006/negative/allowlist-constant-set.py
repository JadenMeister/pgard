# corpus: expect=low
import sqlite3

from flask import request

ALLOWED = {"name", "created_at", "id"}


def run():
    cur = sqlite3.connect("x").cursor()
    sort = request.args.get("sort", "id")
    if sort not in ALLOWED:
        raise ValueError(sort)
    cur.execute("SELECT * FROM t ORDER BY " + sort)
