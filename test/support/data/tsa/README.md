# Test timestamp authority

Key material for the RFC 3161 tests: a self-made certificate authority
and a timestamping certificate it issued, both valid for 100 years so the
fixtures never expire. `make.sh` produced them with OpenSSL; rerun it only
to replace them. The private keys are test fixtures and protect nothing.

At test time, `test/support/local_tsa.py` points an OpenSSL configuration
in a pytest temporary directory at these files and answers HTTP timestamp
queries by running `openssl ts -reply`. Tokens are signed for real; only
the trust anchor is ours. Nothing here is modified by the tests.
