# corpus: expect=PG-SQL-006
from django.db import connection
from django.http import JsonResponse
from django.views import View


class Search(View):
    def get(self, request):
        with connection.cursor() as cur:
            cur.execute("SELECT * FROM t WHERE a = '" + request.GET["a"] + "'")
        return JsonResponse({})
