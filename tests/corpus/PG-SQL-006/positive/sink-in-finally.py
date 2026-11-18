# corpus: expect=PG-SQL-006
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/t")
def table():
    name = request.args["t"]
    cur = sqlite3.connect("x").cursor()
    try:
        if name not in ("users", "orders"):
            raise ValueError("unknown table")
    except ValueError:
        raise
    finally:
        cur.execute("SELECT * FROM " + name)
    return "ok"
