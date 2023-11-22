# The scanner is a CLI program performing the following operations:
#
# - For a given nixpkgs path, evaluates all the known lockfiles (see `extract-lockfiles.nix` in this
#   directory).
#
# - For each of the lockfile, runs a security audit using ecosystem specific tooling (e.g. npm
#   audit, cargo audit, govulncheck, etc.) and postprocesses the results to a common internal format.
#
# - Optionally: dumps results to a local JSON file.
#
# - Optionally: uploads findings to the vendoredvulns frontend via an API endpoint.

import argparse
import functools
import logging
import shutil
import tqdm.contrib.concurrent as tqdm_concurrent

from . import audit, nix, output


def parse_flags():
    parser = argparse.ArgumentParser(
        description="Scan nixpkgs for vulnerabilities in vendored dependencies."
    )

    # Paths to dependencies. We resolve via shutil first to make things cleaner: we need to set both
    # default= and required= based on the results of the resolution of each dependency.
    nix_instantiate_path = shutil.which("nix-instantiate")
    nix_store_path = shutil.which("nix-store")
    cargo_audit_path = shutil.which("cargo-audit")
    npm_path = shutil.which("npm")

    group = parser.add_argument_group("Paths to dependencies")
    group.add_argument(
        "--nix-instantiate-path",
        help="Path to the `nix-instantiate` binary",
        default=nix_instantiate_path,
        required=nix_instantiate_path is None,
    )
    group.add_argument(
        "--nix-store-path",
        help="Path to the `nix-store` binary",
        default=nix_store_path,
        required=nix_store_path is None,
    )
    group.add_argument(
        "--cargo-audit-path",
        help="Path to the `cargo-audit` binary",
        default=cargo_audit_path,
        required=cargo_audit_path is None,
    )
    group.add_argument(
        "--npm-path",
        help="Path to the `npm` binary",
        default=npm_path,
        required=npm_path is None,
    )

    # Input.
    group = parser.add_argument_group("Input to the audit")
    group.add_argument(
        "-i", "--nixpkgs-path", help="Path to the `nixpkgs` to audit", required=True
    )

    # Output.
    group = parser.add_argument_group("Outputs")
    group.add_argument(
        "-o",
        "--output",
        help="Path where the audit results are optionally written (in JSON format)",
    )
    group.add_argument(
        "--upload-api-endpoint",
        help="API endpoint where the audit results are optionally sent",
    )
    group.add_argument(
        "--upload-api-key-file",
        help="Path to the API key used for audit results upload",
    )

    # Development / debugging options.
    group = parser.add_argument_group("Development / debugging")
    group.add_argument(
        "--single",
        help=(
            "If provided, only audit a single package (identified by its `pkgs.`"
            " attrpath)"
        ),
    )
    group.add_argument(
        "-v", "--verbose", help="Log more verbosely", action="store_true"
    )

    return parser.parse_args()


def main():
    flags = parse_flags()

    logging.basicConfig(
        level=logging.DEBUG if flags.verbose else logging.INFO,
        format="{levelname}\t{threadName}\t{message} ({filename}:{lineno})",
        style="{",
    )

    if flags.output is None and flags.upload_api_endpoint is None:
        logging.warning(
            "No output option provided (--output or --upload-api-endpoint), the scanner"
            " will proceed but no results will be stored"
        )

    if flags.single is not None:
        logging.warning(
            "--single=%r used, only a partial scan will be executed", flags.single
        )

    with nix.extract_packages_with_lockfiles(
        nixpkgs_path=flags.nixpkgs_path,
        nix_instantiate_path=flags.nix_instantiate_path,
        nix_store_path=flags.nix_store_path,
        single=flags.single,
    ) as packages:
        audit_package = functools.partial(
            audit.audit_package,
            cargo_audit_path=flags.cargo_audit_path,
            npm_path=flags.npm_path,
        )
        audit_results = tqdm_concurrent.thread_map(audit_package, packages)

    output.summarize(audit_results)

    if flags.output is not None:
        output.output_to_file(audit_results, output_path=flags.output)
        logging.info("Output written to %r", flags.output)

    if flags.upload_api_endpoint is not None:
        logging.error("API upload not yet implemented")


if __name__ == "__main__":
    main()
