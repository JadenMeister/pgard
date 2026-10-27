# corpus: expect=PG-CMD-004
import subprocess

from flask import request


def go():
    return subprocess.getoutput("whoami " + request.args["u"])
