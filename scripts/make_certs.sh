#!/usr/bin/env bash
# make_certs.sh - create a private CA and a TLS certificate for the lab resolver.
# Output (in ./certs, which is git-ignored - NEVER commit these files):
#   ca.crt  - give this to clients (--cafile) so they trust the resolver
#   ca.key  - private key of the CA (only used here to sign)
#   resolver.crt / resolver.key - certificate + private key used by BIND
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p certs
cd certs

if [[ -f resolver.crt && -f ca.crt && "${1:-}" != "--force" ]]; then
    echo "certs/ already exists (use --force to recreate)"; exit 0
fi

# 1) Certificate authority (self-signed, valid ~2 years)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout ca.key -out ca.crt -days 730 -subj "/CN=DNS Lab Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# 2) Resolver key + certificate request
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout resolver.key -out resolver.csr -subj "/CN=resolver.example.test" 2>/dev/null

# 3) Sign it. The SAN lists the name AND the IP, because clients connect to 10.10.2.53.
cat > resolver.ext <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:resolver.example.test,IP:10.10.2.53
EXT
openssl x509 -req -in resolver.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out resolver.crt -days 730 -extfile resolver.ext 2>/dev/null

chmod 600 ca.key resolver.key
rm -f resolver.csr resolver.ext ca.srl
echo "created certs/ca.crt, certs/resolver.crt, certs/resolver.key"
openssl verify -CAfile ca.crt resolver.crt
