# corpus: expect=none
import sqlite3


def vacuum():
    cur = sqlite3.connect("x").cursor()
    for table in ("users", "orders"):
        cur.execute(f"DELETE FROM {table} WHERE expired = 1")
