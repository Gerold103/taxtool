class VaultError(Exception):
    """Base of every error the storage layer raises.

    Messages are written for the person running the tool: they name the
    file or object concerned and what was expected.
    """


class CorruptObjectError(VaultError):
    """A stored blob no longer hashes to its own name."""

    def __init__(self, sha256: str, actual: str) -> None:
        super().__init__(
            f"object {sha256} is corrupt: its content hashes to {actual}"
        )
        self.sha256 = sha256
        self.actual = actual


class HashCollisionError(VaultError):
    """Two different contents share one SHA-256.

    The store keeps the blob it already has. Files in the working tree
    are unaffected; the caller decides whether to continue.
    """

    def __init__(self, sha256: str, what: str) -> None:
        super().__init__(
            f"{what} has the same sha256 as a different stored blob: {sha256}"
        )
        self.sha256 = sha256
