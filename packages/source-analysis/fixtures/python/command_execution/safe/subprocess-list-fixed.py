import subprocess

from flask import Flask

app = Flask(__name__)


@app.route("/version")
def version():
    out = subprocess.run(["git", "--version"], capture_output=True, check=True)
    return out.stdout
