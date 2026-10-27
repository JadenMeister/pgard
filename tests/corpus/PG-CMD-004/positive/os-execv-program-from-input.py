# corpus: expect=PG-CMD-004
import os

from flask import request


def go():
    os.execv(request.args["prog"], ["prog"])
