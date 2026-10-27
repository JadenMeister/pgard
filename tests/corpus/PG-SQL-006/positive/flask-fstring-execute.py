# corpus: expect=PG-SQL-006
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/q")
def handler():
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{request.args['name']}'")
    return {"rows": cur.fetchall()}
