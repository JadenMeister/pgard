# corpus: expect=none
import subprocess


def version():
    return subprocess.run(["git", "--version"], capture_output=True, check=True).stdout
