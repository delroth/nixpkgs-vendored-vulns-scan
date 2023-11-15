# Interface with various lockfile audit command line tools in order to extract vulnerability
# information in a common format.

import dataclasses
import functools
import json
import logging
import pathlib
import subprocess
import tempfile


@dataclasses.dataclass
class Vuln:
    primary_id: str
    aliases: list[str]
    impacts: str


@dataclasses.dataclass
class Result:
    pkg: str
    success: bool
    vulns: list[Vuln]


def audit_cargo(pkg, *, cargo_audit_path):
    cmd = [
        cargo_audit_path,
        "audit",
        "--quiet",
        "--json",
        "-f",
        pkg["lock"],
    ]
    out = subprocess.run(cmd, capture_output=True)

    try:
        # XXX: cargo-audit sometimes prints informational messages on stdout, even in --json mode.
        # We could probably fix that by having an individual vulndb per thread... but not worth it.
        j = json.loads(out.stdout.split(b"\n")[-1])
    except json.JSONDecodeError:
        logging.error(
            "%s: cargo-audit returned unexpected results. stdout: %r, stderr: %r",
            pkg["attr"],
            out.stdout,
            out.stderr,
        )
        return Result(pkg["attr"], False, [])

    vulns = []
    for jvuln in j.get("vulnerabilities", {}).get("list", []):
        primary_id = jvuln["advisory"]["id"]
        aliases = jvuln["advisory"]["aliases"]
        impacts = jvuln["advisory"]["package"]
        vulns.append(Vuln(primary_id, aliases, impacts))

    return Result(pkg["attr"], True, vulns)


def audit_npm(pkg, *, npm_path):
    # npm audit only supports reading a package-lock.json file in its current directory.
    with tempfile.TemporaryDirectory(prefix="vulnpackages-scanner-npm.") as tmpdir:
        tmpdir = pathlib.Path(tmpdir)
        package_lock_link = tmpdir / "package-lock.json"
        package_lock_link.symlink_to(pkg["lock"])

        cmd = [
            npm_path,
            "audit",
            "--json",
        ]
        out = subprocess.run(cmd, cwd=tmpdir, capture_output=True)
        j = json.loads(out.stdout)

    vulns = []
    for jvuln in j.get("vulnerabilities", {}).values():
        # Skip transitive paths, only look at the leaves.
        if isinstance(jvuln["via"][0], str):
            continue

        # TODO: no CVE id?
        primary_id = jvuln["via"][0]["url"]
        aliases = []
        impacts = jvuln["name"]
        vulns.append(Vuln(primary_id, aliases, impacts))

    return Result(pkg["attr"], True, vulns)


def audit_package(pkg, *, cargo_audit_path, npm_path):
    logging.debug("Auditing package %r, type %r", pkg["attr"], pkg["type"])

    funcs = {
        "cargo": functools.partial(audit_cargo, cargo_audit_path=cargo_audit_path),
        "npm": functools.partial(audit_npm, npm_path=npm_path),
    }

    func = funcs.get(pkg["type"])
    if func is None:
        logging.error("%s: unknown package type %r, skipping", pkg["attr"], pkg["type"])
        return Result(pkg["attr"], False, [])

    try:
        return func(pkg)
    except Exception:
        logging.exception("%s: Error while auditing", pkg["attr"])
        return Result(pkg["attr"], False, [])
