fn main() {
    control_positive();
    opaque_dispatch(std::env::var("REACHBENCH_CONTROL").unwrap_or_default().as_str());
}

fn control_positive() {}
fn control_unreachable() {}
fn opaque_dispatch(value: &str) {
    if value == "opaque" { control_opaque(); }
}
fn control_opaque() {}
// This represents explicitly unsupported macro-expansion coverage.
fn control_no_coverage() {}
