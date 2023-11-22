import json
import logging


def summarize(results):
    processed = len(results)
    errors = len([r for r in results if not r.success])
    vulnerable = len([r for r in results if r.vulns])
    total_vulns = sum(len(r.vulns) for r in results)

    logging.info(
        "Processed %d packages. %d errors, %d found with vulnerable dependencies, %d"
        " total vulnerabilities",
        processed,
        errors,
        vulnerable,
        total_vulns,
    )


def results_to_json(results):
    j = {}
    for r in results:
        j[r.pkg.name] = rj = {"success": r.success, "vulns": []}
        for vuln in r.vulns:
            rj["vulns"].append({
                "id": vuln.primary_id, "impacts": vuln.impacts, "aliases": vuln.aliases
            })
    return j


def output_to_file(results, *, output_path):
    with open(output_path, "w") as fp:
        json.dump(results_to_json(results), fp)
