fn entry() {
    reachbench_direct::run();
    if std::env::var("REACHBENCH_DYNAMIC").as_deref() == Ok("dynamic") {
        reachbench_dynamic::run();
    }
}

fn main() {
    entry();
}
