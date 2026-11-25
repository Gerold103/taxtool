"""The OpenTimestamps proof format and calendar protocol, implemented
here directly rather than through the reference library, whose Bitcoin
and crypto dependencies we do not want. The fixtures under
test/support/data/ots prove the two agree.

Bottom up: wire.py encodes integers and byte strings; ops.py and
attestation.py are the two kinds of element in a proof; tree.py is the
proof itself; and file.py wraps a proof as a detached `.ots` file.
Nothing here knows what Bitcoin is beyond "an attestation names a
block height".
"""
