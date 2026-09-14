import os


def handler():
    _step_one()


def _step_one():
    _step_two("ls")


def _step_two(cmd):
    os.system(cmd)


handler()
