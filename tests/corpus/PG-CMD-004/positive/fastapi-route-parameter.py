# corpus: expect=PG-CMD-004
import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping/{host}")
def ping(host: str):
    return subprocess.check_output("ping -c1 " + host, shell=True)
