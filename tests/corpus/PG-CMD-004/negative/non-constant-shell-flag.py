# corpus: expect=low
import subprocess


def run(command, use_shell):
    subprocess.run("echo " + command, shell=use_shell)
