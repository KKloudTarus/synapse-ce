import os


def entry() -> None:
    control_positive()
    opaque_dispatch(os.environ.get("REACHBENCH_CONTROL", ""))


def control_positive() -> None:
    return None


def control_unreachable() -> None:
    return None


def opaque_dispatch(name: str) -> None:
    handler = {"opaque": control_opaque}.get(name)
    if handler is not None:
        handler()


def control_opaque() -> None:
    return None


# Tier configuration excludes generated typing stubs deterministically.
def control_no_coverage() -> None:
    return None


if __name__ == "__main__":
    entry()
