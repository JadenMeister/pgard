# corpus: expect=PG-SQL-006
import psycopg2
from flask import Flask, request

app = Flask(__name__)
conn = psycopg2.connect("dbname=x")


@app.route("/u")
def u():
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % request.args["name"])
    return ""
