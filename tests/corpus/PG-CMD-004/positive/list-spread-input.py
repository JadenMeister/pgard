# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    extra = request.args.getlist("a")
    subprocess.run(["git", "log", *extra])
    return "ok"
