from __future__ import annotations

from iltero_schemas.kinds import RESOURCE_KINDS, TOOL_KINDS, kind_of


def test_every_kind_a_table_gives_is_one_its_provider_lists() -> None:
    for table in TOOL_KINDS.values():
        assert set(table) <= set(RESOURCE_KINDS)
        for provider, types in table.items():
            assert set(types.values()) <= RESOURCE_KINDS[provider]


def test_every_kind_a_provider_lists_is_given_to_some_type() -> None:
    for provider, kinds in RESOURCE_KINDS.items():
        given = {kind for table in TOOL_KINDS.values() for kind in table.get(provider, {}).values()}
        assert given == kinds


def test_a_type_the_table_lacks_has_no_kind() -> None:
    assert kind_of("terraform", "aws", "aws_db_instance") == "rds_instance"
    assert kind_of("terraform", "aws", "aws_new_thing") is None
    assert kind_of("terraform", "google", "google_kms_key") is None
