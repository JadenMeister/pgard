# corpus: expect=PG-CMD-004
import os

from flask import request


def build(x):
    return "ls " + x


def go():
    os.system(build(request.args["x"]))
