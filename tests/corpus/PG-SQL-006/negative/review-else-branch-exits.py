# corpus: expect=low
import re
import sqlite3

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/q")
def handler():
    col = request.args["col"]
    flag = request.args.get("flag")
    cur = sqlite3.connect("app.db").cursor()
    if col in ("name", "id"):
        pass
    else:
        abort(400)
    cur.execute(f"SELECT {col} FROM users")
