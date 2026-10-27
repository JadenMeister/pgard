# corpus: expect=PG-CMD-004
import subprocess

name = input("file: ")
subprocess.run(f"cat {name}", shell=True)
