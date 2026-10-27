# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    subprocess.run(["bash", "-lc", request.args["script"]])
    return "ok"
