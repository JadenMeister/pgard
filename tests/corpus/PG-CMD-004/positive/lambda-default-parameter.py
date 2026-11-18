# corpus: expect=PG-CMD-004
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run_it():
    run = lambda tool, arg="-l": subprocess.run(tool + " " + arg, shell=True)
    run("ls", request.args["x"])
    return "ok"
