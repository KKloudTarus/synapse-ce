from importlib import import_module
from reachbench_direct import run as direct_run


def entry() -> None:
    direct_run()
    module_name = "reachbench_dynamic"
    import_module(module_name).run()


entry()
