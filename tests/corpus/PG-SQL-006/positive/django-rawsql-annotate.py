# corpus: expect=PG-SQL-006
from django.db.models.expressions import RawSQL
from django.http import JsonResponse

from .models import User


def search(request):
    users = User.objects.annotate(x=RawSQL("select " + request.GET["col"], []))
    return JsonResponse({"n": users.count()})
