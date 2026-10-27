# corpus: expect=low
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    import re
    host = request.args["host"]
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return "bad", 400
    os.system("ping -c 1 " + host)
    return "ok"
