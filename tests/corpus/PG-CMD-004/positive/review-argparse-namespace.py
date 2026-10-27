# corpus: expect=PG-CMD-004
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument("path")
args = parser.parse_args()
os.system("ls -l " + args.path)
