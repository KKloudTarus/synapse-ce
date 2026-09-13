import os


def handler():
    _run_query("ls")


def _run_query(cmd):
    os.system(cmd)


handler()
