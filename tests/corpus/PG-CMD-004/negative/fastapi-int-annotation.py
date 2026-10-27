# corpus: expect=low
import os

from fastapi import FastAPI

app = FastAPI()


@app.get("/wait/{seconds}")
def wait(seconds: int):
    os.system(f"sleep {seconds}")
