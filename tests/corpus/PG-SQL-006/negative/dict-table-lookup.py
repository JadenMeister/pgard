# corpus: expect=low
import sqlite3

from flask import request

ORDERS = {"new": "created_at DESC", "old": "created_at ASC"}


def run():
    cur = sqlite3.connect("x").cursor()
    order = ORDERS.get(request.args.get("o"), "id")
    cur.execute("SELECT * FROM t ORDER BY " + order)
    cur.execute(f"SELECT * FROM t ORDER BY {ORDERS[request.args['o']]}")
