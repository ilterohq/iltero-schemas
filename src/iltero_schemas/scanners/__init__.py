"""The scanner releases the Iltero CLI runs itself, and what each one is (see ``pin``)."""

from iltero_schemas.scanners.pin import (
    SCANNER_PIN,
    CheckovLock,
    CheckovRelease,
    ScannerPin,
    TrivyProgram,
    TrivyRelease,
)

__all__ = ["SCANNER_PIN", "CheckovLock", "CheckovRelease", "ScannerPin", "TrivyProgram", "TrivyRelease"]
