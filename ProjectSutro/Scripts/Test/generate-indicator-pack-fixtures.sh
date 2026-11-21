#!/bin/zsh
#
#  generate-indicator-pack-fixtures.sh
#  Mac Monitor
#
#  Makes the test indicator packs IndicatorPackVerifier's and
#  SavedIndicatorSet's tests read: one signed correctly and a few signed
#  wrongly, and two releases to install, with test certificates made here.
#  Running it again replaces them all.
#
#  Author: Brandon Dalton
#
#  Usage: generate-indicator-pack-fixtures.sh [output folder]
#  Output: the indicator-pack files in SutroESFrameworkTests/Fixtures, or in
#          the folder given
#

set -euo pipefail

OPENSSL=/usr/bin/openssl
PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$(cd "${1:-$PROJECT_DIR/SutroESFrameworkTests/Fixtures}" && pwd)"
WORK="$(/usr/bin/mktemp -d)"
trap '/bin/rm -rf "$WORK"' EXIT
cd "$WORK"

/bin/cat > ca.cnf <<'EOF'
[ ca ]
default_ca = test_ca

[ test_ca ]
database = index.txt
new_certs_dir = .
serial = serial
default_md = sha256
policy = any_name
unique_subject = no
email_in_dn = no

[ any_name ]
commonName = supplied
organizationalUnitName = optional
organizationName = optional
countryName = optional

[ req ]
distinguished_name = placeholder
prompt = no

[ placeholder ]
CN = placeholder

[ root ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ intermediate ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
1.2.840.113635.100.6.2.6 = ASN1:NULL

[ developer_id ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
1.2.840.113635.100.6.1.13 = ASN1:NULL

[ not_developer_id ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
: > index.txt
echo 1000 > serial

# A certificate: a new key, and its request signed by an issuer, or by itself.
#   $1 name, $2 subject, $3 extensions section, $4 notBefore, $5 notAfter, $6 issuer's name or "self"
certificate() {
    "$OPENSSL" req -new -newkey rsa:2048 -nodes -keyout "$1.key" -subj "$2" -config ca.cnf -out "$1.csr" 2>/dev/null
    local issuer=(-cert "$6.pem" -keyfile "$6.key")
    [[ "$6" == self ]] && issuer=(-selfsign -keyfile "$1.key")
    "$OPENSSL" ca -batch -notext -config ca.cnf "${issuer[@]}" -subj "$2" -extensions "$3" \
        -startdate "$4" -enddate "$5" -in "$1.csr" -out "$1.pem" 2>/dev/null
}

certificate root "/CN=Mac Monitor Test Root CA/O=Mac Monitor Tests" root 160101000000Z 460101000000Z self
certificate intermediate "/CN=Mac Monitor Test Developer ID CA/O=Mac Monitor Tests" intermediate \
    160101000000Z 460101000000Z root
LEAF="/CN=Developer ID Application: Test Signer (ABCDE12345)/OU=ABCDE12345/O=Test Signer"
certificate leaf "$LEAF" developer_id 260101000000Z 460101000000Z intermediate
certificate expired "$LEAF" developer_id 200101000000Z 210101000000Z intermediate
certificate plain "/CN=Test Signer (ABCDE12345)/OU=ABCDE12345/O=Test Signer" not_developer_id \
    260101000000Z 460101000000Z intermediate
/bin/cat intermediate.pem root.pem > chain.pem

# The payload: an empty pack, as tools/mmilib/pack.py encodes one (sorted keys, two-space indents, a line break).
/bin/cat > payload.json <<'EOF'
{
  "format": "com.swiftlydetecting.indicators",
  "indicators": [],
  "pack": {
    "commit": "0000000000000000000000000000000000000000",
    "core": [],
    "min_engine": "3.2.0",
    "published": "2026-11-15T00:00:00Z",
    "retired": [],
    "sequence": 1
  },
  "version": 2
}
EOF
echo '{"format": "com.swiftlydetecting.indicators", "version": 2, "indicators": []}' > other.json

# Two releases to install: pack 2, and pack 3, which changes one indicator again and adds one that needs a newer
# Mac Monitor. SavedIndicatorSetPackTests says what each indicator is for.
#   $1 the pack's sequence, a digit, which its commit repeats, $2 the first indicator's revision,
#   $3 the first indicator's predicate, $4 more entries
release() {
    local commit="$(printf '%040d' 0)"
    commit="${commit//0/$1}"
    /bin/cat > "payload-$1.json" <<EOF
{
  "format": "com.swiftlydetecting.indicators",
  "indicators": [
    {
      "color": "red",
      "description": "Ran a fixture's program.",
      "id": "7A000000-0000-4000-8000-000000000001",
      "isEnabled": true,
      "minEngine": "3.2.0",
      "name": "Fixture program ran",
      "predicate": "$3",
      "revision": $2,
      "severity": "medium",
      "symbol": "bolt",
      "tableMarks": [
        "dot"
      ],
      "tactic": "execution"
    },
    {
      "color": "orange",
      "description": "Deleted a file's quarantine attribute.",
      "id": "7A000000-0000-4000-8000-000000000002",
      "isEnabled": true,
      "minEngine": "3.2.0",
      "name": "Fixture quarantine removed",
      "predicate": "event.deleteextattr != nil AND event.deleteextattr.extattr ENDSWITH \\"apple.quarantine\\"",
      "revision": 1,
      "severity": "low",
      "symbol": "xmark.shield",
      "tableMarks": [
        "dot"
      ],
      "tactic": "defenseImpairment"
    },
    {
      "color": "blue",
      "description": "Ran another of a fixture's programs.",
      "id": "7A000000-0000-4000-8000-000000000004",
      "isEnabled": false,
      "minEngine": "3.2.0",
      "name": "Fixture program ran too",
      "predicate": "event.exec != nil AND process.executable.path == \\"/usr/bin/false\\"",
      "revision": 1,
      "severity": "low",
      "symbol": "bolt",
      "tableMarks": [
        "dot"
      ]
    }$4
  ],
  "pack": {
    "commit": "$commit",
    "core": [
      "7A000000-0000-4000-8000-000000000001"
    ],
    "min_engine": "3.2.0",
    "published": "2026-11-16T00:00:00Z",
    "retired": [
      "7A000000-0000-4000-8000-000000000009"
    ],
    "sequence": $1
  },
  "version": 2
}
EOF
}
release 2 2 'event.exec != nil AND process.executable.path == \"/usr/bin/true\"' ''
release 3 3 'event.exec != nil AND process.executable.path IN {\"/usr/bin/true\", \"/usr/bin/yes\"}' ',
    {
      "id": "7A000000-0000-4000-8000-000000000005",
      "kind": "a kind of rule 3.2 does not know",
      "minEngine": "9.0.0",
      "name": "Fixture from a newer Mac Monitor"
    }'

# A detached CMS signature, DER, SHA-256, with the chain. Extra arguments go to `openssl cms`.
#   $1 output, $2 content
sign() {
    local out="$1" content="$2"
    shift 2
    "$OPENSSL" cms -sign -binary -md sha256 -outform DER -in "$content" -certfile chain.pem "$@" -out "$out"
}

# The pack file as tools/mmilib/pack.py's PackBuilder.wrapped writes it.
#   $1 output, $2 payload, $3 signature
wrap() {
    local format='{\n  "format": "%s",\n  "version": 1,\n  "payload": "%s",\n  "signature": "%s"\n}\n'
    printf "$format" com.swiftlydetecting.indicator-pack "$(/usr/bin/base64 -i "$2")" "$(/usr/bin/base64 -i "$3")" \
        > "$OUT/$1"
}

sign valid.der payload.json -signer leaf.pem -inkey leaf.key
sign expired.der payload.json -signer expired.pem -inkey expired.key
sign plain.der payload.json -signer plain.pem -inkey plain.key
sign two.der payload.json -signer leaf.pem -inkey leaf.key -signer plain.pem -inkey plain.key
sign attached.der other.json -signer leaf.pem -inkey leaf.key -nodetach
sign release-2.der payload-2.json -signer leaf.pem -inkey leaf.key
sign release-3.der payload-3.json -signer leaf.pem -inkey leaf.key

/bin/cp payload.json "$OUT/indicator-pack-payload.json"
wrap indicator-pack.json payload.json valid.der
wrap indicator-pack-expired.json payload.json expired.der
wrap indicator-pack-not-developer-id.json payload.json plain.der
wrap indicator-pack-two-signers.json payload.json two.der
wrap indicator-pack-attached.json payload.json attached.der
wrap indicator-pack-2.json payload-2.json release-2.der
wrap indicator-pack-3.json payload-3.json release-3.der
"$OPENSSL" x509 -in root.pem -outform DER -out "$OUT/indicator-pack-root.cer"
"$OPENSSL" x509 -in leaf.pem -outform DER -out "$OUT/indicator-pack-signer.cer"

echo "Wrote the indicator pack fixtures to $OUT"
