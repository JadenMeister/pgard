# corpus: expect=low
import subprocess

from flask import request

TOOLS = {"zip": "zip", "gz": "gzip"}


def run():
    tool = TOOLS.get(request.args.get("kind"), "gzip")
    subprocess.run([tool, "-d", "a"])
