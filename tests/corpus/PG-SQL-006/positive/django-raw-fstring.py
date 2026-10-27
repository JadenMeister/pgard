# corpus: expect=PG-SQL-006
from django.db import connection
from django.http import JsonResponse

from .models import User


def search(request):
    rows = User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{request.POST['u']}'")
    return JsonResponse({"n": len(list(rows))})
