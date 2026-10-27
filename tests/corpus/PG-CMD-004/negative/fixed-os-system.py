# corpus: expect=none
import os


def clean():
    os.system("rm -rf /tmp/cache")
    os.system("echo " + "done")
