# corpus: expect=low
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/q")
def handler():
    import re
    col = request.args["col"]
    if not re.fullmatch(r"[a-z_]+", col):
        return "bad", 400
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT {col} FROM users")
    return {}
