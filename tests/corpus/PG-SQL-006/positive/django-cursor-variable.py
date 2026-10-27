# corpus: expect=PG-SQL-006
from django.db import connection
from django.http import JsonResponse

from .models import User


def purge(request):
    cursor = connection.cursor()
    sql = "DELETE FROM sessions WHERE user = '%s'" % request.GET["u"]
    cursor.execute(sql)
    return JsonResponse({})
