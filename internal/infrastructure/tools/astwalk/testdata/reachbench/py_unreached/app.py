import os


def handler():
    return 1


def _unused_admin_action(cmd):
    os.system(cmd)


handler()
