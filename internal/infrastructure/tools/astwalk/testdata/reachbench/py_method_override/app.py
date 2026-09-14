import os


class Base:
    def run(self):
        self._step()

    def _step(self):
        return 0


class Derived(Base):
    def _step(self):
        os.system("id")


def handler():
    d = Derived()
    d.run()


handler()
