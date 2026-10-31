"""The names of the change types and activities the contract knows.

A **change type** is the kind of thing a change changes; an **activity** is
one kind of work a single record describes. The names stand alone, so every
module that names a change type, from an assertion to a record, uses this one
list (``change_types`` holds what each declares).
"""

from __future__ import annotations

from typing import Final, Literal

# The change types the contract knows. Anything else is refused.
ChangeTypeName = Literal["iac_change"]
# The activities the contract knows, each the name of a record body.
ActivityName = Literal["iac_change"]
# The change type of a change made with an infrastructure-as-code (IaC) tool, whichever tool made it, and the one
# activity it is made of.
IAC_CHANGE_TYPE: Final = "iac_change"
