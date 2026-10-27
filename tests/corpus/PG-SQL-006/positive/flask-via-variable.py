# corpus: expect=PG-SQL-006
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/q")
def handler():
    name = request.args["name"]
    query = f"SELECT * FROM users WHERE name = '{name}'"
    conn = sqlite3.connect("app.db")
    conn.execute(query)
    return {}
