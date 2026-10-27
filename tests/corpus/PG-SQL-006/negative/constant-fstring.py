# corpus: expect=none
import sqlite3

TABLE = "users"
COLUMNS = "id, name"


def run(name):
    cur = sqlite3.connect("x").cursor()
    cur.execute(f"SELECT {COLUMNS} FROM {TABLE} WHERE name = ?", (name,))
