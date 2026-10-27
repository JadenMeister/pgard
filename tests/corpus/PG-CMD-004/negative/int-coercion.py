# corpus: expect=low
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def handler():
    count = int(request.args["count"])
    os.system(f"ping -c {count} 127.0.0.1")
    subprocess.run(["tail", "-n", str(count), "app.log"])
    return "ok"
