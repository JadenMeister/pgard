# corpus: expect=none
import subprocess


def tar():
    cmd = ["tar", "czf"]
    cmd.append("out.tgz")
    cmd.extend(["a", "b"])
    cmd += ["c"]
    subprocess.run(cmd, check=True)
