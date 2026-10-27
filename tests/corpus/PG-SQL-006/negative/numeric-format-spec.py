# corpus: expect=low
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/q")
def handler():
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users LIMIT %d" % int(request.args["n"]))
    cur.execute(f"SELECT * FROM users OFFSET {request.args['o']:d}")
    return {}
