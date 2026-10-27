import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/convert")
def convert():
    name = request.args["name"]
    subprocess.run(f"convert {name} out.png", shell=True, check=True)
    return "ok"
