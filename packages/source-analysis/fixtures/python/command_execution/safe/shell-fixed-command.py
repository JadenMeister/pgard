import os
import subprocess

COMMAND = "uptime"


def uptime():
    os.system("uptime")
    return subprocess.check_output(COMMAND, shell=True)
