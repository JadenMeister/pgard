# corpus: expect=low
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/q")
def handler():
    page = request.args["page"]
    if not page.isdigit():
        return "bad", 400
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users LIMIT 10 OFFSET " + page)
    return {}
