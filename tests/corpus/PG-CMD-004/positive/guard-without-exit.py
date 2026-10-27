# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    tool = request.args["tool"]
    if tool not in ("gzip", "xz"):
        print("unexpected tool")
    subprocess.run([tool, "-d", "a.gz"])
    return "ok"
