import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    os.system("ping -c 1 " + request.args["host"])
    return "ok"
