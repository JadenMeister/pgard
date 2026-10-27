# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


ALIASES = {"gz": "gzip", "xz": "xz"}


@app.route("/c")
def handler():
    kind = request.args["kind"]
    tool = ALIASES.get(kind, kind)
    subprocess.run(tool + " -d a", shell=True)
