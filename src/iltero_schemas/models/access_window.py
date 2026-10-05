"""The access window of one stage of a governed run: when its run token was issued and when it expires.

A pipeline job asks the server for a run token: a short-lived credential for
one stage of a run the server opened. The answer gives the server's time and
the token's expiry, and names the CI job it verified. A record keeps those two
times for each stage (``StageAccessWindow``), beside the stage's
``ci_identity`` from the same answer. The window is the run token's validity:
it is not a change window, and says nothing about approval of the change.

Both times are the server's, as the writer copied them; the record is not
signed, so only the server can confirm them. A stage's ``observed_at`` comes
from the runner's clock, which may differ, so it is not compared with them.
"""

from __future__ import annotations

from pydantic import model_validator

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Timestamp, instant


class StageAccessWindow(StrictModel):
    """The server's time in the answer that issued a stage's run token, and when that token expires."""

    issued_at: Timestamp
    expires_at: Timestamp

    @model_validator(mode="after")
    def _expires_after_it_was_issued(self) -> StageAccessWindow:
        if instant(self.expires_at) <= instant(self.issued_at):
            raise ValueError("a stage's run token expires after it was issued")
        return self
