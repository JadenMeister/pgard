# corpus: expect=none
import sqlite3

from fastapi import FastAPI

app = FastAPI()
db = sqlite3.connect("app.db")


@app.get("/search")
def search(q: str):
    return db.execute("SELECT * FROM items WHERE name LIKE ?", (f"%{q}%",)).fetchall()
