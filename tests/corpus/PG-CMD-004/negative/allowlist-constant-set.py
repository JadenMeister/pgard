# corpus: expect=low
import subprocess

from flask import request

TOOLS = {"gzip", "bzip2", "xz"}


def run():
    tool = request.args["tool"]
    if tool not in TOOLS:
        raise ValueError(tool)
    subprocess.run([tool, "-d", "a"])
