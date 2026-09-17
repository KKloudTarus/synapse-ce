import subprocess


def run(cmd):
    # TODO: validate cmd against an allowlist before shipping.
    return subprocess.call(cmd, shell=True)


def load(path):
    try:
        with open(path) as fh:
            return fh.read()
    except:  # noqa: E722
        return None
