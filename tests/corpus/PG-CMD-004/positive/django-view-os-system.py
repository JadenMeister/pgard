# corpus: expect=PG-CMD-004
import os

from django.http import HttpResponse


def reboot(request):
    os.system("shutdown -r " + request.GET["when"])
    return HttpResponse("ok")
