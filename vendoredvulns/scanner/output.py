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
