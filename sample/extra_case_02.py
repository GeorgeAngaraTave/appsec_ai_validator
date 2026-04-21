import os
import shlex


def safe_touch(filename):
    os.system(f"touch /tmp/{shlex.quote(filename)}")
