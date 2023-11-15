# Recurses over all of nixpkgs to find derivations that have vendored
# dependencies and extract the required lockfiles and/or other metadata to
# perform a vulnerability scan.
#
# Heavily inspired by nixpkgs-crate-holes by sterni, licensed under the MIT
# license: https://code.tvl.fyi/tree/users/sterni/nixpkgs-crate-holes/default.nix
#
# Usage:
# $ nix-build extract-lockfiles.nix -A single --argstr attr 'PKGNAME'
# or
# $ nix-build extract-lockfiles.nix -A full
#
# The output is a JSON file containing all derivations with known vendoring, as
# well as a path to their lock file. The lock file format is dependent on the
# type of each derivation (e.g. Cargo, NPM, ...), no common format is used.

let
  pkgs = import <nixpkgs> { allowBroken = false; };
  lib = pkgs.lib;

  # buildNpmPackage handling

  isNpmPackage = v: v ? npmDeps;
  extractNpmLock = drv:
    if ! (drv ? npmDeps.outPath)
    then null
    else
      pkgs.runCommand "${drv.name}-package-lock.json" { } ''
        cp ${drv.npmDeps}/package-lock.json $out
      '';

  # buildRustPackage handling

  isCargoPackage = v: v ? cargoDeps;
  extractCargoLock = drv:
    if !(drv ? cargoDeps.outPath)
    then null
    else
      pkgs.runCommand "${drv.name}-Cargo.lock" { } ''
        if test -d "${drv.cargoDeps}"; then
          cp "${drv.cargoDeps}/Cargo.lock" "$out"
        fi

        if test -f "${drv.cargoDeps}"; then
          tar -xO \
            --no-wildcards-match-slash --wildcards \
            -f "${drv.cargoDeps}" \
            '*/Cargo.lock' \
            > "$out"
        fi
      '';

  # nixpkgs traversal

  analyzeDrv = path: drv:
    let
      commonAttrs = {
        attr = path;
        maintainers = drv.meta.maintainers or [ ];
      };

      isNpm = tryEvalOrFalse (isNpmPackage drv);
      isCargo = tryEvalOrFalse (isCargoPackage drv);

      langSpecific =
        if isNpm then {
          type = "npm";
          lock = extractNpmLock drv;
        } else if isCargo then {
          type = "cargo";
          lock = extractCargoLock drv;
        } else
          null;
    in
    if langSpecific != null then commonAttrs // langSpecific else null;

  # Condition for us to recurse: Either at top-level or recurseForDerivation.
  recurseInto = path: x: path == [ ] ||
    (lib.isAttrs x && (x.recurseForDerivations or false));

  # Returns the value or false if an eval error occurs.
  tryEvalOrFalse = v: (builtins.tryEval v).value;

  /* Traverses nixpkgs as instructed by `recurseInto` and collects
     the attribute and lockfile derivation of every rust package it
     encounters into a list.

     Type :: attrs
          -> list {
               attr :: list<str>;
               lock :: option<drv>;
               maintainers :: list<maintainer>;
             }
  */
  allResults =
    let
      go = path: x:
        let
          isDrv = tryEvalOrFalse (lib.isDerivation x);
          doRec = tryEvalOrFalse (recurseInto path x);

          result = if isDrv then analyzeDrv path x else null;
        in
        if doRec then
          lib.concatLists
            (
              lib.mapAttrsToList (n: go (path ++ [ n ])) x
            )
        else if result != null then [ result ]
        else [ ];
    in
    go [ ];

  reportSingle = { attr }:
    let
      path = lib.splitString "." attr;
      drv = lib.getAttrFromPath [ attr ] pkgs;
    in
    pkgs.writeText "report-${attr}.json" (builtins.toJSON ([ (analyzeDrv path drv) ]));

  reportFull =
    pkgs.writeText "report-full.json" (builtins.toJSON (allResults pkgs));

in
{
  single = reportSingle;
  full = reportFull;
}
