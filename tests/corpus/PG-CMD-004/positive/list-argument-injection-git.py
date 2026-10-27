# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    ref = request.args["ref"]
    subprocess.run(["git", "log", ref])
    return "ok"
