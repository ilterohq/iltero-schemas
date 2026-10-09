"""The tool-keyed parts the neutral models carry, one name per part, and the checks that join two of them.

Each name is the union of every tool's variant of that part, chosen by its
``tool`` value. Only Terraform exists yet, so each is Terraform's model. A new
tool adds its module and joins its variant to each union here, as
``Annotated[TerraformX | OtherX, Field(discriminator="tool")]``, with a check
that the variant names the tool the enclosing document names. No neutral model
changes.
"""

from __future__ import annotations

from iltero_schemas.models.tools.terraform import (
    TerraformApplyData,
    TerraformIdentityData,
    TerraformRelatedData,
    TerraformResourceData,
    check_deposed,
)

# What only the tool that planned a resource says about it.
ResourceToolData = TerraformResourceData
# What only that tool says about a resource that refers to it.
RelatedToolData = TerraformRelatedData
# What only the tool that wrote the apply log says about the apply, and the checks against its changes.
ApplyToolData = TerraformApplyData
# What only the tool that wrote the state says in an identity document.
IdentityToolData = TerraformIdentityData


def check_identity_against_apply(identity: IdentityToolData, apply: ApplyToolData) -> None:
    """Raise ``ValueError`` unless the identity document's tool part agrees with the apply's."""
    check_deposed(identity, apply)
