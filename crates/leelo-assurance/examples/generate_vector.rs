#[allow(dead_code)]
#[path = "../tests/support/mod.rs"]
mod support;

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&support::vector()).unwrap()
    );
}
