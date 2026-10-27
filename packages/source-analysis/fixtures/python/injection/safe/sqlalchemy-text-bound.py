from fastapi import FastAPI
from sqlalchemy import text

app = FastAPI()
TABLE = "orders"


@app.get("/orders")
def orders(status: str, session):
    query = text(f"SELECT * FROM {TABLE} WHERE status = :status")
    return session.execute(query, {"status": status}).all()
