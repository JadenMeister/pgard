# corpus: expect=PG-CMD-004
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)
import shlex


@app.route("/run")
def handler():
    host = shlex.quote(request.args["host"])
    subprocess.run("ping " + host, shell=True)
    return "ok"
