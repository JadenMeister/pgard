import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (request.args["name"],))
    return {"rows": cur.fetchall()}
