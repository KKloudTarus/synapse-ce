import os


class Runner:
    def run(self, cmd):
        self._do(cmd)

    def _do(self, cmd):
        os.system(cmd)


r = Runner()
r.run("ls")
