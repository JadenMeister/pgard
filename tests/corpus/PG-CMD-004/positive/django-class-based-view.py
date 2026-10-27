# corpus: expect=PG-CMD-004
import subprocess

from django.http import HttpResponse
from django.views import View


class Run(View):
    def post(self, request):
        subprocess.run("make " + request.POST["target"], shell=True)
        return HttpResponse("ok")
