# corpus: expect=PG-SQL-006
import sqlite3


def find(cur, name):
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
