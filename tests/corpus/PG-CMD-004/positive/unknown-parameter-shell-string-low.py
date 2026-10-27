# corpus: expect=PG-CMD-004
import os


def thumbs(directory, name):
    os.system("convert " + directory + "/" + name + " thumb.png")
