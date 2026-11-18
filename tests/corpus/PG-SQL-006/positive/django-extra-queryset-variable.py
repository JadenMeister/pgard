# corpus: expect=PG-SQL-006
from django.http import HttpResponse

from .models import Book


def search(request):
    books = Book.objects.filter(published=True)
    books = books.extra(where=["title = '%s'" % request.GET["title"]])
    return HttpResponse(str(list(books)))
