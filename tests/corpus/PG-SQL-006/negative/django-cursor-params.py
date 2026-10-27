# corpus: expect=none
from django.db import connection
from django.http import JsonResponse

from .models import User


def purge(request):
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM sessions WHERE user = %s", [request.GET["u"]])
    return JsonResponse({})
