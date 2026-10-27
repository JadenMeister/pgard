# corpus: expect=none
import sqlite3


def run(cur, sql):
    cur.execute(sql)
