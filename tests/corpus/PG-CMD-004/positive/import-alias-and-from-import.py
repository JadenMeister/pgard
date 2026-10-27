# corpus: expect=PG-CMD-004
import subprocess as sp
from os import system as run_shell

from flask import request


def go():
    sp.run("a " + request.args["a"], shell=True)
    run_shell("b " + request.args["b"])
