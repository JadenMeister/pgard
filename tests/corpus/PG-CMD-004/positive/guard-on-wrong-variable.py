# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    host = request.args["host"]
    other = "x"
    if not other.isalnum():
        return "bad"
    os.system("ping " + host)
    return "ok"
