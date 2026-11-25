"""The conformance vectors shipped with the package (see ``paths``), and the files their records kept (see
``kept_files``)."""

from iltero_schemas.vectors.kept_files import case_files_of, kept_files_of, kept_files_of_case
from iltero_schemas.vectors.paths import HAND_MADE_RECORDS, VECTORS

__all__ = ["HAND_MADE_RECORDS", "VECTORS", "case_files_of", "kept_files_of", "kept_files_of_case"]
