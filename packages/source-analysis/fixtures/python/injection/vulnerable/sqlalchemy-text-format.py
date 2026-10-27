from fastapi import FastAPI
from sqlalchemy import text

app = FastAPI()


@app.get("/orders")
def orders(status: str, session):
    return session.execute(text("SELECT * FROM orders WHERE status = '{}'".format(status))).all()
