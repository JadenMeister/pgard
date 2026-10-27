# corpus: expect=low
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    subprocess.run(["git", "log", "--end-of-options", request.args["ref"], "--"])
    return "ok"
