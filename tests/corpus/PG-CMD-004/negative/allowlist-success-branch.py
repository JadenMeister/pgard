# corpus: expect=low
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    tool = request.args["tool"]
    if tool in ("gzip", "xz"):
        subprocess.run([tool, "-d", "a.gz"])
    return "ok"
