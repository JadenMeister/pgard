# corpus: expect=PG-SQL-006
from django.db import connection
from django.http import JsonResponse

from .models import User


def purge(request):
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM sessions WHERE user = " + request.GET["u"])
    return JsonResponse({})
