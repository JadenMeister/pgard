# corpus: expect=low
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args["host"]
    if not host.replace(".", "").isalnum():
        return "bad host", 400
    subprocess.run("ping -c 1 " + host, shell=True)
    return "ok"
