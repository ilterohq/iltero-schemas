"""Resource kinds: the closed lists a selector names (see ``vocabulary``), and each tool's table (see ``tables``)."""

from iltero_schemas.kinds.tables import TOOL_KINDS, kind_of
from iltero_schemas.kinds.vocabulary import RESOURCE_KINDS

__all__ = ["RESOURCE_KINDS", "TOOL_KINDS", "kind_of"]
