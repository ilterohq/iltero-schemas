"""The conformance vectors shipped with the package (see ``paths``), and the files their records kept (see
``kept_files``)."""

from iltero_schemas.vectors.kept_files import case_files_of, kept_files_of, kept_files_of_case
from iltero_schemas.vectors.paths import VECTORS

__all__ = ["VECTORS", "case_files_of", "kept_files_of", "kept_files_of_case"]
