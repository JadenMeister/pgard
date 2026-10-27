# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    name = request.args["name"]
    subprocess.run(f"convert {name} out.png", shell=True, check=True)
    return "ok"
