# corpus: expect=PG-SQL-006
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/t")
def table():
    cur = sqlite3.connect("x").cursor()
    query = lambda name: cur.execute("SELECT * FROM " + name)
    return str(query(request.args["t"]))
