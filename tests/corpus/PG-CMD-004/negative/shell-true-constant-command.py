# corpus: expect=none
import subprocess

COMMAND = "uptime | cut -d, -f1"


def load():
    return subprocess.check_output(COMMAND, shell=True)
