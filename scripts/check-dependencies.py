#!/usr/bin/env python3
"""Check explicit requirements and both locked production and fuzz graphs."""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def check_graph(manifest, *, all_features=False):
    manifest_arguments = ["--manifest-path", str(manifest)]
    features = ["--all-features"] if all_features else []
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps",
         *manifest_arguments, *features],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    metadata = json.loads(result.stdout)
    for package in metadata["packages"]:
        for dependency in package["dependencies"]:
            if dependency["source"] is not None and dependency["req"] == "*":
                raise RuntimeError(
                    f"unconstrained dependency: {package['name']} -> {dependency['name']}"
                )
    subprocess.run(
        ["cargo", "deny", "--locked", "--workspace", *manifest_arguments, *features,
         "check", "--config", str(ROOT / "deny.toml"), "--hide-inclusion-graph",
         "advisories", "bans", "licenses", "sources"],
        cwd=ROOT, check=True,
    )


def main():
    check_graph(ROOT / "Cargo.toml")
    # libFuzzer is optional for ordinary deterministic tests, but its complete
    # enabled graph is included in the same advisory/source/license policy.
    check_graph(ROOT / "fuzz" / "Cargo.toml", all_features=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"dependency policy failed: {error}", file=sys.stderr)
        sys.exit(1)
