# corpus: expect=low
from flask import request


def run(cur):
    query = cur.mogrify("SELECT * FROM t WHERE a = %s", (request.args["a"],))
    cur.execute(query)
