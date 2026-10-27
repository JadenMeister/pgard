# corpus: expect=PG-SQL-006
from fastapi import FastAPI
from sqlalchemy import text

app = FastAPI()


@app.get("/orders/{status}")
def orders(status: str, session):
    return session.execute(text(f"SELECT * FROM orders WHERE status = '{status}'")).all()
