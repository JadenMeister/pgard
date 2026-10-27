# corpus: expect=none
from concurrent.futures import ThreadPoolExecutor
from flask import request


def run(executor: ThreadPoolExecutor):
    executor.execute(request.args["task"])
