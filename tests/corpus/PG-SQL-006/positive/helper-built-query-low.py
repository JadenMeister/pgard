# corpus: expect=PG-SQL-006
import sqlite3

from flask import request


def build(where):
    return "SELECT * FROM t WHERE " + where


def run():
    cur = sqlite3.connect("x").cursor()
    cur.execute(build(request.args["w"]))
