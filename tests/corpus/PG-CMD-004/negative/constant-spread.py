# corpus: expect=none
import subprocess

FLAGS = ["-n", "5"]


def recent():
    subprocess.run(["git", "log", *FLAGS], check=True)
