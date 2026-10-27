import subprocess

from django.http import HttpResponse


def archive(request):
    target = request.GET["target"]
    subprocess.check_output(["sh", "-c", "tar czf out.tgz " + target])
    return HttpResponse("done")
