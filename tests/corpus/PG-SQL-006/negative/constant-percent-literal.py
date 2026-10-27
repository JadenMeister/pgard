# corpus: expect=none
import sqlite3


def run():
    cur = sqlite3.connect("x").cursor()
    cur.execute("SELECT * FROM %s" % "users")
    cur.execute("SELECT * FROM {}".format("users"))
