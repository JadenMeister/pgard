# corpus: expect=PG-SQL-006
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/q")
def handler():
    name = request.args.get("name")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return {}
