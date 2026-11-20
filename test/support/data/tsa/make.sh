#!/bin/bash
# Generates the key material of the test timestamp authority: a CA and a
# TSA certificate valid for 100 years. Run once; the outputs are committed
# so tests do no key generation. The keys are test fixtures, not secrets.
set -euo pipefail
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 -nodes -days 36500 \
    -keyout ca.key -out ca.pem -subj "/CN=taxtool test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:2048 -nodes \
    -keyout tsa.key -out tsa.csr -subj "/CN=taxtool test TSA"
printf 'extendedKeyUsage=critical,timeStamping\n' > ext.cnf
printf 'keyUsage=critical,digitalSignature\n' >> ext.cnf
openssl x509 -req -in tsa.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 36500 -out tsa.pem -extfile ext.cnf
rm -f tsa.csr ext.cnf ca.srl
openssl x509 -in tsa.pem -noout -dates -ext extendedKeyUsage
