# corpus: expect=PG-CMD-004
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run_it():
    run = lambda c: subprocess.run(c, shell=True)
    run(request.args["x"])
    return "ok"
