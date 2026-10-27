# corpus: expect=low
import sqlite3

from fastapi import FastAPI

app = FastAPI()
db = sqlite3.connect("app.db")


@app.get("/items/{item_id}")
def item(item_id: int):
    return db.execute(f"SELECT * FROM items WHERE id = {item_id}").fetchone()
