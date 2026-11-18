# corpus: expect=none
from flask import Flask, request

app = Flask(__name__)


class Ctx:
    def extra(self, where=()):
        return list(where)


@app.route("/c")
def context():
    return str(Ctx().extra(where=["a = " + request.args["a"]]))
