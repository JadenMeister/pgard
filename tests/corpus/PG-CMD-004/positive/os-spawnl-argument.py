# corpus: expect=PG-CMD-004
import os

from flask import request


def go():
    os.spawnl(os.P_WAIT, "/bin/ls", "ls", request.args["d"])
