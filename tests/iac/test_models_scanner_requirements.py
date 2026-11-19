"""A group of scanners a run requires can be met for every assertion its members are mapped to."""

from __future__ import annotations

from iltero_schemas.ast.document import load_document
from iltero_schemas.models.common.assertion import TechnicalAssertion
from iltero_schemas.models.common.scanners import ScannerRequirement
from iltero_schemas.models.iac.scanner_requirements import MAPS_NOTHING, scanner_requirement_problems
from iltero_schemas.scanner_check_mappings.iac.shipped import SHIPPED_MAPPING
from tests.conftest import STARTER_ASSERTIONS

ASSERTIONS = [
    TechnicalAssertion.model_validate(load_document(path.read_text(encoding="utf-8")))
    for path in sorted(STARTER_ASSERTIONS.glob("*.yaml"))
]


def _problems(*groups: list[str]) -> list[tuple[str, str]]:
    requirements = [ScannerRequirement.model_validate({"any_of": group}) for group in groups]
    return scanner_requirement_problems(requirements, ASSERTIONS, [SHIPPED_MAPPING])


def test_a_group_with_a_member_that_reports_passes_can_be_met() -> None:
    assert _problems(["checkov"]) == []
    assert _problems(["checkov", "trivy"]) == []


def test_a_group_of_only_a_tool_that_reports_only_failures_cannot_be_met_where_scanners_alone_decide() -> None:
    assert _problems(["trivy"]) == [
        (
            "scanner_requirements.0",
            f"can never be met for {assertion} at the plan stage: every member mapped to it names resources only when "
            "they fail",
        )
        for assertion in (
            "ILT.IAC.RESOURCE.AWS.CLOUDTRAIL.RECORDS_ALL_REGIONS",
            "ILT.IAC.RESOURCE.AWS.CLOUDTRAIL.VALIDATES_LOG_FILES",
        )
    ]


def test_a_tool_that_reports_only_failures_can_meet_a_group_where_the_assertion_has_its_own_condition() -> None:
    """Trivy is mapped to assertions with a condition of their own, such as RDS.NOT_PUBLIC, and to the two
    CloudTrail assertions only scanners decide: only the latter are listed."""
    listed = {what.split()[5] for _, what in _problems(["trivy"])}
    mapped = {
        entry.assertion.id
        for entry in SHIPPED_MAPPING.spec.assertion_mappings
        for checks in entry.scanner_checks
        if checks.tool == "trivy"
    }
    assert listed < mapped
    assert "ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC" in mapped - listed


def test_a_group_none_of_whose_members_is_mapped_to_any_assertion_is_listed() -> None:
    assert scanner_requirement_problems(
        [ScannerRequirement.model_validate({"any_of": ["checkov"]})], ASSERTIONS, []
    ) == [("scanner_requirements.0", MAPS_NOTHING)]


def test_a_group_mapped_only_to_assertions_outside_the_run_requires_nothing_and_is_listed() -> None:
    others = [assertion for assertion in ASSERTIONS if not assertion.metadata.id.startswith("ILT.IAC.RESOURCE")]
    assert scanner_requirement_problems(
        [ScannerRequirement.model_validate({"any_of": ["checkov"]})], others, [SHIPPED_MAPPING]
    ) == [("scanner_requirements.0", MAPS_NOTHING)]
