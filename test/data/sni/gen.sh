#!/bin/sh
#
# Regenerate the SNI test certificates in this directory.
#
#   root-ca.pem          Root CA (cert only)
#   server-interm.pem    Leaf retest.server.org + key + intermediate CA
#   client-interm.pem    Leaf retest.client.org + key + intermediate CA
#   server-verifyhost.pem Self-signed retest.server.org with IP:127.0.0.1 SAN
#
# Hostnames must be in subjectAltName: OpenSSL >= 4.1 no longer falls back
# to the subject CN for hostname verification.
#
# The CA private keys are discarded. Set OPENSSL to use another binary.
#
# Usage: ./gen.sh

set -eu

OPENSSL=${OPENSSL:-openssl}
DAYS=36500
SUBJ="/C=AU/ST=Some-State/O=Retest"

OUT=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

cat > ext.cnf <<'EOF'
[interm]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[server]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:retest.server.org
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[client]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:retest.client.org
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

genkey() {
	"$OPENSSL" ecparam -name prime256v1 -genkey -out "$1"
}

serial() {
	echo "0x$("$OPENSSL" rand -hex 16)"
}

# sign <name> <cn> <ca> <extensions>
sign() {
	genkey "$1.key"
	"$OPENSSL" req -new -key "$1.key" -subj "$SUBJ/CN=$2" -out "$1.csr"
	"$OPENSSL" x509 -req -sha256 -in "$1.csr" \
		-CA "$3.pem" -CAkey "$3.key" -set_serial "$(serial)" \
		-days $DAYS -extfile ext.cnf -extensions "$4" -out "$1.pem"
}

# Root CA
genkey root.key
"$OPENSSL" req -new -x509 -sha256 -key root.key \
	-subj "$SUBJ/CN=Mr Retest Root CA" -days $DAYS \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-out root.pem

# Intermediate CA and leaf certificates
sign interm "Mr Retest Intermediate CA" root   interm
sign server "retest.server.org"         interm server
sign client "retest.client.org"         interm client

# Self-signed server cert for hostname + IP-literal verification
genkey verifyhost.key
"$OPENSSL" req -new -x509 -sha256 -key verifyhost.key \
	-subj "$SUBJ/CN=retest.server.org" -days $DAYS \
	-addext "subjectAltName=DNS:retest.server.org,IP:127.0.0.1" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-out verifyhost.pem

# Sanity check
"$OPENSSL" verify -CAfile root.pem -untrusted interm.pem \
	-verify_hostname retest.server.org server.pem
"$OPENSSL" verify -CAfile root.pem -untrusted interm.pem \
	-verify_hostname retest.client.org client.pem
"$OPENSSL" verify -CAfile verifyhost.pem \
	-verify_hostname retest.server.org verifyhost.pem

cp root.pem "$OUT/root-ca.pem"
cat server.pem server.key interm.pem > "$OUT/server-interm.pem"
cat client.pem client.key interm.pem > "$OUT/client-interm.pem"
cat verifyhost.pem verifyhost.key   > "$OUT/server-verifyhost.pem"

echo "Certificates written to $OUT"
