# corpus: expect=none
import sqlite3


class Repo:
    TABLE = "accounts"

    def find(self, name):
        cur = sqlite3.connect("x").cursor()
        cur.execute(f"SELECT * FROM {self.TABLE} WHERE name = ?", (name,))
        cur.execute(f"SELECT * FROM {Repo.TABLE}")
