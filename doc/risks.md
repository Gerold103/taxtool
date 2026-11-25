# Known risks and their limits

What a seal proves, what it does not, and every way we know of in which
the records could still be wrong or forged. This document exists so that
an auditor can judge the evidence with the same knowledge the author has.
It is updated whenever the design or the code changes what is possible.

Likelihood scale: certain, plausible, remote, theoretical. Severity says
what a reader could wrongly believe if the risk materialised.

## What a seal proves

A seal fixes the SHA-256 of every file in the data directory in manifests,
hashes the manifests into one root hash, and has that hash timestamped by
external authorities. From then on, anyone with the directory and standard
tools can show that a sealed file has, or has not, the bytes it had at the
time of the timestamp. Each seal also records the hash of the previous
seal, so the seals form one chain.

A seal says nothing about the time before it, nothing about whether a
document was genuine when it was filed, and nothing about files that were
never sealed.

## Fabrication before the first seal covering an event

Likelihood: certain, in the sense that the window always exists.
Severity: an event could have been invented or edited at any time between
its stated date and the timestamp of the first seal that covers it.

Until a seal covers an event it is an ordinary file the owner can write
freely. Every seal therefore carries a period of uncertainty: the gap
between the dates of the events it covers and its own timestamp. The gap
is visible in the data itself, an auditor should read it as such, and the
only mitigation is to seal often. The GoBD accept recording by the end of
the following month; a seal within that window keeps the gap inside the
legally accepted one.

## Backdating within the gap

Likelihood: plausible. Severity: an event dated early in the gap could
have been written late in the gap.

The same window seen from the other side. An event dated the 3rd and
sealed on the 30th may have been written on the 29th. Nothing in the
records distinguishes the two. Mitigation as above.

## Rebuilding the whole history

Likelihood: plausible in motive, visible in effect. Severity: an entire
history could be fabricated with consistent seals.

The owner holds every byte and could delete `.tax/`, rewrite the logs and
seal everything again. The new tokens would carry the dates on which they
were obtained, so every seal would be later than the events it covers by
the full delay of the rewrite. A history whose seals all postdate their
events by months is the trace. Sending each seal's root hash to a third
party at seal time, for example to the tax consultant by e-mail, removes
the possibility: the rebuilt seals would not match the hashes already in
someone else's hands.

## Dropping the newest seals

Likelihood: plausible. Severity: recent events could be removed or
changed and the records would still verify up to an earlier seal.

The chain detects a missing seal in the middle, because the next seal
names the hash of the one before it, but it cannot detect a missing tail:
if the last three seals are deleted, the chain simply ends three seals
earlier, and the events they covered become unsealed and editable. The
same external copy of the latest root hash closes this, since a reader who
knows the latest hash can see that the chain does not reach it.

## Hash collision by accident

Likelihood: theoretical, about one in 10^69 for a lifetime of ten
thousand documents. Severity: none for the proofs; two documents share a
hash and both remain verifiable.

Two different files with one SHA-256 are both kept in the working tree,
both appear in manifests under their own paths, and both hash to their
sealed value. The object store holds one blob for the pair and reports the
collision when the second is stored. Only restoring an older version of
one of them from the store becomes ambiguous.

## Content swap with the same hash

Likelihood: theoretical; no method is known, and the cost of finding a
second input for a given SHA-256 is about 2^256 operations. Severity: if
it were ever feasible, a sealed file could be replaced by different bytes
and every hash-based check would still pass.

This is the inherent limit of a hash proof and applies equally to every
timestamp authority, code-signing system and blockchain. Size is recorded
next to the hash, which rules out replacements of a different length. The
design re-stamps old seals with each new one so that a stronger hash can
be introduced later without breaking the chain; details when that code
exists.

## Authority weaknesses

Likelihood: remote for a supervised authority, certain for the local
one. Severity: a token could be forged or backdated.

The local HMAC authority used in tests and examples proves nothing to
anyone but the owner, who holds the key; it is a stand-in. A real
authority's signing key could be compromised, or its operator could
collude with the owner. Mitigations: at least two independent
authorities per seal, preference for qualified authorities under eIDAS
supervision whose certificates appear in the EU Trusted List, and
optionally an anchor in a public blockchain, which no single operator
controls.

## Bitcoin anchor limits

Likelihood: plausible for the time gap, remote for the rest. Severity: a
reader could take the anchor for more than it is.

An OpenTimestamps proof shows that the root hash is a leaf of the merkle
tree in one Bitcoin block header, which is saved next to the proof. The
header passes its own proof of work, and that is all that can be checked
offline. Three limits follow.

The height is a claim. The proof names a block height, but nothing in
the saved header proves it is the block at that height; a forged header
with a trivial amount of work could be saved next to a forged proof.
An auditor confirms the saved header's hash against any block explorer
or a full node, which takes seconds and turns the claim into evidence.
The hash is `block-header.bin` hashed twice with SHA-256 and shown
reversed, as every explorer displays it.

The time is the block time. A block's timestamp is set by its miner and
is accurate to roughly an hour by Bitcoin's own rules, and the block
itself comes hours after the seal, since calendars batch submissions.
The anchor therefore proves "existed no later than this block", an
upper bound, not the sealing minute. The sealing time in `stamp.yaml`
is the owner's own claim, and the calendar's pending attestation holds
no time at all, only the calendar's address. An RFC 3161 authority on
the same seal supplies the precise time from the operator's clock.

A proof can stay pending. Until the calendar's transaction is mined the
proof is only the calendar's promise, `root.pending.ots`, which proves
nothing on its own. If the calendar disappears before that, the proof
never completes. Sealing therefore attempts at least one authority but
requires no proof to be complete, and a dead proof can be abandoned
explicitly, leaving a marker file that the next seal covers. A seal
whose proofs are all abandoned is a weak link, not a broken chain: the
next seal's authorities still cover its root hash.

## Algorithm and certificate aging

Likelihood: certain over decades. Severity: an old token might no longer
be checkable with current software or trust.

Signing certificates expire, roots expire, algorithms weaken. To be
written together with the re-stamping code; the intended answer is that
each new seal covers the previous seal's proof files, so the newest token
vouches for all older ones.

## Loss of the proofs

Likelihood: plausible without backups. Severity: the data stays readable
but the evidence of its integrity is gone.

`.tax/seals/` holds the manifests and tokens; losing it leaves plain
files with no proof. Backups of the whole directory and the external copy
of root hashes are the remedy. Losing `.tax/objects/` loses only history
and undo, not proof.

## What sealing never covers

Likelihood: not applicable. Severity: a reader could take integrity for
authenticity.

A seal proves that a file has not changed since it was filed. It does not
prove that the bank statement was issued by the bank, that the invoice
was ever sent, or that the exchange rate evidence was read correctly.
Those remain questions for the documents themselves and for the
counterparties, exactly as with paper.
