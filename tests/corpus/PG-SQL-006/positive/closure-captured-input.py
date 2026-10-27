# corpus: expect=PG-SQL-006
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/c")
def handler():
    name = request.args["name"]
    cur = sqlite3.connect("app.db").cursor()

    def run():
        cur.execute("SELECT * FROM t WHERE n = '" + name + "'")

    run()
    return ""
