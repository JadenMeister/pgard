# corpus: expect=low
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


ALIASES = {"gz": "gzip", "xz": "xz"}


@app.route("/c")
def handler():
    tool = ALIASES.get(request.args.get("kind"), "gzip")
    subprocess.run(tool + " -d a", shell=True)
