//! detox CLI. Contracts: SLICES.md slices 1–4.
//! Modes: `detox-rs --strings ...` (pure), `detox-rs [check] PATH...` (plan, default),
//! `detox-rs --apply PATH...` / `run`, `detox-rs undo [--last|--run ID]`,
//! `detox-rs extract -i FILE|- -d DIR ...`. Each mode lives in `cli/`.

mod cli;

fn main() {
    std::process::exit(cli::run());
}
