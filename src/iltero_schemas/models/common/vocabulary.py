"""Names that consumers of the contract write as plain values.

Some fields hold an open string, such as the scheme an identifier is written
in. Each consumer must spell such a value the same way. A constant gives a
value one spelling that every consumer can import.
"""

from __future__ import annotations

from typing import Final

# A deployment named by its Iltero unit: the part of a project that is planned and applied as one.
SCHEME_UNIT: Final = "iltero_unit"
