# OpenTimestamps interoperability fixtures

`hello-world.txt` and `hello-world.txt.ots` are the example files
published by the OpenTimestamps client project. The proof commits the
SHA-256 of the text file to Bitcoin block 358391 directly, without a
calendar, which is why it has no pending attestation and verifies with
nothing but the block header.

`block-358391.bin` is the 80-byte header of that block, fetched once from
a public block explorer. Its double SHA-256 is the block hash
`000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319`, which
anyone can confirm against any explorer or a full node, and its merkle
root is what the proof's final digest must equal.

The tests parse the proof with our own codec, serialize it back to the
identical bytes, and verify it offline against the header. That is the
check that our reading of the format matches the reference
implementation. Nothing here is modified by the tests.
