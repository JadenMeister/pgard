# corpus: expect=low
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/q")
def handler():
    limit = int(request.args.get("limit", "10"))
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT * FROM users LIMIT {limit}")
    return {}
