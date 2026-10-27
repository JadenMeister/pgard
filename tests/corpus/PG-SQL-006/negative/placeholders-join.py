# corpus: expect=none
import sqlite3


def run(ids):
    cur = sqlite3.connect("x").cursor()
    marks = ",".join(["?"] * len(ids))
    cur.execute(f"SELECT * FROM t WHERE id IN ({marks})", ids)
    cur.execute("SELECT * FROM t WHERE id IN (%s)" % ",".join("?" for _ in ids), ids)
