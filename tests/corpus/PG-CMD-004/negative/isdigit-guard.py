# corpus: expect=low
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    n = request.args["n"]
    if not n.isdigit():
        return "bad", 400
    os.system("sleep " + n)
    return "ok"
