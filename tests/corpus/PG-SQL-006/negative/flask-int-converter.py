# corpus: expect=low
import sqlite3

from flask import Flask

app = Flask(__name__)


@app.route("/items/<int:item_id>")
def item(item_id):
    cur = sqlite3.connect("x").cursor()
    cur.execute("SELECT * FROM items WHERE id = " + item_id)
    return ""
