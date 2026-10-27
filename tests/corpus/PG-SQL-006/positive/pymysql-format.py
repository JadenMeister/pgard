# corpus: expect=PG-SQL-006
import pymysql
from flask import Flask, request

app = Flask(__name__)


@app.route("/u")
def u():
    cur = pymysql.connect(host="h").cursor()
    cur.execute("SELECT * FROM users WHERE name = '{0}'".format(request.args["name"]))
    return ""
