# corpus: expect=PG-CMD-004
import asyncio

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping")
async def ping(host: str):
    proc = await asyncio.create_subprocess_exec("ping", host)
    await proc.wait()
