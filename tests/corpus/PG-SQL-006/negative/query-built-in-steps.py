# corpus: expect=none
import sqlite3


def run(name):
    cur = sqlite3.connect("x").cursor()
    query = "SELECT * FROM users"
    query += " WHERE name = ?"
    query += " ORDER BY id"
    cur.execute(query, (name,))
