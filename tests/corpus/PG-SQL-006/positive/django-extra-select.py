# corpus: expect=PG-SQL-006
from django.db import connection
from django.http import JsonResponse

from .models import User


def search(request):
    users = User.objects.extra(select={"x": "length(" + request.GET["col"] + ")"})
    return JsonResponse({"n": users.count()})
