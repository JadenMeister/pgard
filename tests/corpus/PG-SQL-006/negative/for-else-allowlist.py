# corpus: expect=low
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/t")
def table():
    name = request.args["t"]
    for allowed in ("users", "orders"):
        if name == allowed:
            break
    else:
        raise ValueError("unknown table")
    cur = sqlite3.connect("x").cursor()
    return str(cur.execute("SELECT * FROM " + name))
