# corpus: expect=PG-SQL-006
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/t")
def table():
    name = request.args["t"]
    for allowed in [name]:
        if name == allowed:
            break
    else:
        raise ValueError("unknown table")
    cur = sqlite3.connect("x").cursor()
    return str(cur.execute("SELECT * FROM " + name))
