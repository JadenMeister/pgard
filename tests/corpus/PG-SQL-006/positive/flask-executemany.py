# corpus: expect=PG-SQL-006
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/q")
def handler():
    rows = request.get_json()
    cur = sqlite3.connect("app.db").cursor()
    cur.executemany("INSERT INTO t VALUES ('" + rows["a"] + "')", [])
    return {}
