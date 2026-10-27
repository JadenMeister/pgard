# corpus: expect=PG-SQL-006
import asyncpg
from fastapi import FastAPI

app = FastAPI()


@app.get("/u")
async def u(name: str):
    conn = await asyncpg.connect("postgres://x")
    return await conn.fetch(f"SELECT * FROM users WHERE name = '{name}'")
