# Interface with Nix command line tools in order to extract package and lockfiles informations from
# a given nixpkgs.

import contextlib
import importlib.resources
import json
import logging
import pathlib
import subprocess
import tempfile


def instantiate(*, tmpdir, nixpkgs_path, nix_instantiate_path, single):
    logging.info("Evaluating extract-lockfiles.nix on input nixpkgs (%s)", nixpkgs_path)

    drv_path = tmpdir / "result.drv"

    resources = importlib.resources.files(__package__)
    with importlib.resources.as_file(
        resources.joinpath("extract-lockfiles.nix")
    ) as nix_expr_file:
        cmd = [
            str(nix_instantiate_path),
            "--add-root",
            str(drv_path),
            str(nix_expr_file),
        ]

        if single is not None:
            cmd.extend([
                "-A",
                "single",
                "--argstr",
                "attr",
                single,
            ])
        else:
            cmd.extend(["-A", "full"])

        logging.debug("Running command %r", cmd)
        subprocess.run(cmd, check=True)

    return drv_path


def realise(*, tmpdir, drv_path, nix_store_path):
    logging.info("Building extract-lockfiles derivation")

    out_path = tmpdir / "result.json"

    cmd = [
        str(nix_store_path),
        "--add-root",
        str(out_path),
        "--realise",
        str(drv_path),
    ]

    logging.debug("Running command %r", cmd)
    subprocess.run(cmd, check=True)

    return out_path


def gc(*, nix_store_path):
    logging.info("Garbage collecting Nix store")

    cmd = [str(nix_store_path), "--gc"]

    logging.debug("Running command %r", cmd)
    subprocess.run(cmd, check=True)


@contextlib.contextmanager
def extract_packages_with_lockfiles(
    *, nixpkgs_path, nix_instantiate_path, nix_store_path, single
):
    with tempfile.TemporaryDirectory(prefix="vulnpackages-scanner-eval.") as tmpdir:
        tmpdir = pathlib.Path(tmpdir)
        logging.debug("Evaluation temporary directory: %s", tmpdir)

        drv_path = instantiate(
            tmpdir=tmpdir,
            nixpkgs_path=nixpkgs_path,
            nix_instantiate_path=nix_instantiate_path,
            single=single,
        )

        output_path = realise(
            tmpdir=tmpdir,
            drv_path=drv_path,
            nix_store_path=nix_store_path,
        )

        with output_path.open() as output_fp:
            yield json.load(output_fp)

    gc(nix_store_path=nix_store_path)
