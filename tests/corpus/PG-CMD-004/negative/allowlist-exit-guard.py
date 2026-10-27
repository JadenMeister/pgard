# corpus: expect=low
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)
from flask import abort


@app.route("/run")
def handler():
    tool = request.args["tool"]
    if tool not in ("gzip", "bzip2", "xz"):
        abort(400)
    subprocess.run([tool, "-d", "a.gz"])
    return "ok"
