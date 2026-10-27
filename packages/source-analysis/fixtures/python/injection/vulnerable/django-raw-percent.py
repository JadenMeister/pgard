from django.http import JsonResponse

from .models import User


def search(request):
    name = request.GET.get("name", "")
    rows = User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % name)
    return JsonResponse({"users": [row.username for row in rows]})
