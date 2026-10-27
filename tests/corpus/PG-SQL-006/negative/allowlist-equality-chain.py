# corpus: expect=low
import sqlite3

from flask import request


def run():
    cur = sqlite3.connect("x").cursor()
    direction = request.args.get("dir")
    if direction == "asc":
        cur.execute("SELECT * FROM t ORDER BY id " + direction)
