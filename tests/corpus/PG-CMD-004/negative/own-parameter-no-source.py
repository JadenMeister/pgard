# corpus: expect=low
import subprocess


def thumbs(directory, name):
    subprocess.run("convert " + directory + "/" + name + " thumb.png", shell=True)
