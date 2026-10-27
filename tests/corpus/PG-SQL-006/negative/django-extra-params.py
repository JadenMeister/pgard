# corpus: expect=none
from django.db import connection
from django.http import JsonResponse

from .models import User


def search(request):
    q = request.GET["q"]
    users = User.objects.extra(where=["username = %s"], params=[q])
    return JsonResponse({"n": users.count()})
