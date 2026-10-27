# corpus: expect=none
import subprocess

BASE = ["git", "log", "--oneline"]


def recent():
    return subprocess.run(BASE + ["-n", "5"], capture_output=True, check=True).stdout
