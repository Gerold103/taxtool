"""Storage layer: hashes, blobs, manifests, seals and proofs.

Knows nothing about the application built on top of it: no events, no
periods, not even the name of its own directory. A test enforces that the
application's name never appears in this package or its tests, so that
it stays extractable as a repository of its own.
"""
