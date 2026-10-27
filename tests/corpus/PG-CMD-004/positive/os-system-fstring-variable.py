# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    host = request.args["host"]
    os.system(f"ping -c 1 {host}")
    return "ok"
