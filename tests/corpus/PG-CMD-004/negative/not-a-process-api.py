# corpus: expect=none
from flask import request


class Runner:
    def system(self, command):
        return command


def go(runner):
    runner.system("echo " + request.args["x"])
