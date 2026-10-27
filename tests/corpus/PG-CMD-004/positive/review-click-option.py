# corpus: expect=PG-CMD-004
import os

import click


@click.command()
@click.option("--target")
def clean(target):
    os.system(f"rm -rf {target}")
