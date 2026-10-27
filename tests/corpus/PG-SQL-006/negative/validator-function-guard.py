# corpus: expect=low
import sqlite3
from flask import abort

from flask import Flask, request

app = Flask(__name__)


@app.route("/q")
def handler():
    col = request.args["col"]
    if not is_valid_column(col):
        abort(400)
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT {col} FROM users")
    return {}
