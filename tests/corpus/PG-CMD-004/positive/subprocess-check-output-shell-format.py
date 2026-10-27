# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    out = subprocess.check_output("grep {} log.txt".format(request.args["q"]), shell=True)
    return out
