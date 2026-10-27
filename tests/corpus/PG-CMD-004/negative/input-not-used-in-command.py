# corpus: expect=none
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/echo")
def echo():
    host = request.args["host"]
    subprocess.run(["uptime"], check=True)
    return host
