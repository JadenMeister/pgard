# corpus: expect=PG-SQL-006
import re
import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/q")
def handler():
    col = request.args["col"]
    flag = request.args.get("flag")
    cur = sqlite3.connect("app.db").cursor()
    try:
        if col not in ("name", "id"):
            raise ValueError(col)
    except ValueError:
        pass
    cur.execute(f"SELECT {col} FROM users")
