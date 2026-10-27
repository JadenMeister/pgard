# corpus: expect=PG-SQL-006
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/q")
def handler():
    col = request.args["col"]
    sort = "id"
    if sort not in ("name", "id"):
        return "bad"
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT {col} FROM users ORDER BY {sort}")
    return {}
