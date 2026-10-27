# corpus: expect=none
import subprocess


def pipeline():
    p = subprocess.Popen(["ls", "-l"], stdout=subprocess.PIPE)
    q = subprocess.Popen(["wc", "-l"], stdin=p.stdout, stdout=subprocess.PIPE)
    return q.communicate()
