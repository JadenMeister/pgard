# corpus: expect=none
import sqlite3

TABLE = "users"


def count():
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT COUNT(*) FROM {TABLE}")
