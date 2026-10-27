# corpus: expect=PG-SQL-006
from .models import Article


def search(request):
    return Article.objects.extra(select={"hit": "title LIKE '%" + request.GET["q"] + "%'"})
