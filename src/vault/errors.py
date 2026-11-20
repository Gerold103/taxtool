class VaultError(Exception):
    """Base of every error the storage layer raises.

    Messages are written for the person running the tool: they name the
    file or object concerned and what was expected.
    """
