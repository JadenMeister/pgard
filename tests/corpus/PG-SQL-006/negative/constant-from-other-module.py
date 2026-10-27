# corpus: expect=low
import sqlite3

from .config import USERS_TABLE


def run(name):
    cur = sqlite3.connect("x").cursor()
    cur.execute(f"SELECT * FROM {USERS_TABLE} WHERE name = ?", (name,))
