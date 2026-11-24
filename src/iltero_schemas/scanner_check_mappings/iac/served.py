"""Whether a scanner check mapping the server serves decides the starter assertions as the mapping Iltero ships does.

A stage of a run the server opened applies only the mapping the server served it, so the starter assertions this
package ships are decided by scanner checks only if the served mapping carries them. Their entries have one source,
the shipped mapping: for each starter assertion the shipped mapping decides, the served mapping holds that entry,
unchanged, and it decides no other starter assertion. An entry for an assertion that is not a starter is the served
mapping's own and is not compared with anything here.
"""

from __future__ import annotations

from iltero_schemas.assertions.built_in import SHIPPED_ASSERTIONS
from iltero_schemas.models.iac.scanner_check_mapping import ScannerCheckMapping
from iltero_schemas.scanner_check_mappings.iac.shipped import SHIPPED_MAPPING


def served_mapping_problems(mapping: ScannerCheckMapping) -> list[tuple[str, str]]:
    """Each way ``mapping``, a mapping the server serves, does not decide the starter assertions as the shipped
    mapping does, as (where, what) pairs: a starter assertion the shipped mapping decides that it leaves out, an entry
    for a starter assertion that is not the shipped one, and an entry for a starter assertion the shipped mapping does
    not decide. Empty for a mapping built from the shipped one."""
    shipped = {entry.assertion.id: entry for entry in SHIPPED_MAPPING.spec.assertion_mappings}
    served = {entry.assertion.id: (index, entry) for index, entry in enumerate(mapping.spec.assertion_mappings)}
    problems: list[tuple[str, str]] = []
    for assertion_id in sorted(set(shipped) - set(served)):
        problems.append(("spec.assertion_mappings", f"leaves out the shipped entry for {assertion_id}"))
    for assertion_id, (index, entry) in served.items():
        if assertion_id not in SHIPPED_ASSERTIONS:
            continue
        where = f"spec.assertion_mappings.{index}"
        if assertion_id not in shipped:
            problems.append((where, "decides a starter assertion the shipped mapping does not decide"))
        elif entry != shipped[assertion_id]:
            problems.append((where, "is not the shipped entry for its starter assertion"))
    return problems
