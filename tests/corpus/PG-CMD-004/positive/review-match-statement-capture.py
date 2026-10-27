# corpus: expect=PG-CMD-004
import os
import sys


def main():
    match sys.argv[1:]:
        case ["clean", target]:
            os.system(f"rm -rf {target}")
        case _:
            pass
