# corpus: expect=low
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/c")
def handler():
    for host in request.args.getlist("h"):
        if not host.isalnum():
            continue
        os.system("ping -c1 " + host)
