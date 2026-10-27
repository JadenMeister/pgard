# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)
import shlex


@app.route("/run")
def handler():
    argv = shlex.split(request.args["cmd"])
    subprocess.run(argv)
    return "ok"
