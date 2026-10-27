# corpus: expect=PG-SQL-006
from .models import Article


def search(request):
    return Article.objects.raw("SELECT * FROM blog_article WHERE slug = '" + request.GET["s"] + "'")
