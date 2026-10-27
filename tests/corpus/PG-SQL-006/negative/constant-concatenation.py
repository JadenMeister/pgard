# corpus: expect=none
import sqlite3

BASE = "SELECT * FROM users"


def run(name):
    cur = sqlite3.connect("x").cursor()
    cur.execute(BASE + " WHERE name = ? ORDER BY id", (name,))
