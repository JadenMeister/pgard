# corpus: expect=PG-SQL-006
import pandas as pd
from flask import request


def report(conn):
    return pd.read_sql(f"SELECT * FROM sales WHERE region = '{request.args['r']}'", conn)
