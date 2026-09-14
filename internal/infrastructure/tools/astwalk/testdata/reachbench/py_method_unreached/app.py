import os


class Service:
    def handle(self):
        return 1

    def _unused(self, cmd):
        os.system(cmd)


s = Service()
s.handle()
