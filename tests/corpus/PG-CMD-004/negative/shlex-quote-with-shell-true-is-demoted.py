# corpus: expect=low
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)
import shlex


@app.route("/run")
def handler():
    name = shlex.quote(request.args["name"])
    subprocess.run(f"convert {name} out.png", shell=True)
    return "ok"
