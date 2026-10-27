# corpus: expect=PG-SQL-006
import sqlite3

from flask import request


class Repo:
    TABLE = "users"

    def find(self):
        cur = sqlite3.connect("app.db").cursor()
        cur.execute(f"SELECT * FROM {self.TABLE} WHERE name = '{request.args['n']}'")
