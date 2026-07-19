#!/bin/bash
#
#  Copyright (c) 2026, The OpenThread Registrar Authors.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#

# Add a Commissioner certificate/key to an EXISTING credentials/<vendor>/ set,
# signed by that set's Domain CA. This fills the gap for credential sets that
# were created before CredentialGenerator generated a Commissioner - the main
# create-credentials-pem.sh only writes a fresh, complete set into a new
# directory and cannot add a single missing role to an existing one.
#
# The generated Commissioner matches what CredentialGenerator.make() produces:
#  - EC P-256 key, SHA256withECDSA signature, 5-year validity
#  - signed by the Domain CA (domain_ca.pem / privkey_domain_ca.pem)
#  - extensions: SubjectKeyIdentifier, AuthorityKeyIdentifier,
#    BasicConstraints{critical, CA:FALSE} - and NO KeyUsage/EKU (the Java code
#    passes null extra-extensions for the Commissioner role)
#  - key written as an SEC1 "EC PRIVATE KEY" PEM, as JcaPEMWriter emits.
# For testing only.

set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "Usage: $0 <vendor> [subject-dn]"
  echo "  <vendor>      existing credentials/<vendor>/ directory to add a commissioner to"
  echo "  [subject-dn]  optional OpenSSL subject, e.g. '/C=NL/L=Utrecht/O=acme/CN=acme commissioner'"
  echo "                (default follows CredentialGenerator's naming - see SUBJECT below)"
  exit 1
fi

readonly VENDOR="$1"
readonly DIR="./credentials/${VENDOR}"
readonly CA_CERT="${DIR}/domain_ca.pem"
readonly CA_KEY="${DIR}/privkey_domain_ca.pem"
readonly OUT_CERT="${DIR}/commissioner.pem"
readonly OUT_KEY="${DIR}/privkey_commissioner.pem"

# Subject distinguished name for the Commissioner. Default reflects the naming
# used by CredentialGenerator.make() (see dnamePrefix() + COMMISSIONER_ALIAS):
#   C=NL, L=Utrecht, O=<vendor>, CN=<vendor> commissioner
# Override via the 2nd argument to match a hand-crafted set. For example, for
# the 'ietf-cbrski' set (whose Domain CA is "Custom-ER Global CA"), a subject
# matching its Registrar peer would be:
#   '/C=CA/ST=ON/L=Ottowa/O=Custom-ER, Inc./OU=Office ops/CN=Custom-ER Commercial Buildings Commissioner'
readonly SUBJECT="${2:-/C=NL/L=Utrecht/O=${VENDOR}/CN=${VENDOR} commissioner}"

# ~5 years, matching Constants.CERT_VALIDITY = Period.ofYears(5).
readonly DAYS=1826

# --- checks ---------------------------------------------------------------
[ -d "${DIR}" ]      || { echo "error: no such credentials directory: ${DIR}"; exit 1; }
[ -f "${CA_CERT}" ]  || { echo "error: missing Domain CA certificate: ${CA_CERT}"; exit 1; }
[ -f "${CA_KEY}" ]   || { echo "error: missing Domain CA private key: ${CA_KEY}"; exit 1; }
[ -e "${OUT_CERT}" ] && { echo "error: refusing to overwrite existing: ${OUT_CERT}"; exit 1; }
[ -e "${OUT_KEY}" ]  && { echo "error: refusing to overwrite existing: ${OUT_KEY}"; exit 1; }

# --- generate -------------------------------------------------------------
readonly TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "Generating Commissioner for '${VENDOR}'"
echo "  subject: ${SUBJECT}"
echo "  issuer : $(openssl x509 -in "${CA_CERT}" -noout -subject -nameopt oneline,-esc_msb | sed 's/^subject= *//')"

# EC P-256 private key, as an SEC1 "EC PRIVATE KEY" PEM (as JcaPEMWriter emits).
openssl ecparam -name prime256v1 -genkey -noout -out "${OUT_KEY}"

# Certificate request for the commissioner subject.
openssl req -new -key "${OUT_KEY}" -subj "${SUBJECT}" -out "${TMP}/commissioner.csr"

# Extensions: mirror CredentialGenerator's default trio for a leaf with no
# extra extensions (no KeyUsage, no ExtendedKeyUsage). authorityKeyIdentifier
# 'keyid' copies the Domain CA's SubjectKeyIdentifier, so the AKI matches.
cat >"${TMP}/commissioner.ext" <<'EOF'
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
basicConstraints       = critical, CA:FALSE
EOF

# Random positive serial (CredentialGenerator uses a random ~159-bit serial).
openssl x509 -req \
  -in "${TMP}/commissioner.csr" \
  -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
  -set_serial "0x$(openssl rand -hex 16)" \
  -days "${DAYS}" -sha256 \
  -extfile "${TMP}/commissioner.ext" \
  -out "${OUT_CERT}"

# --- verify ---------------------------------------------------------------
# Chain to the Domain CA, and confirm key/cert public keys agree.
openssl verify -no_check_time -CAfile "${CA_CERT}" "${OUT_CERT}" >/dev/null
cert_pub="$(openssl x509 -in "${OUT_CERT}" -noout -pubkey)"
key_pub="$(openssl pkey -in "${OUT_KEY}" -pubout)"
[ "${cert_pub}" = "${key_pub}" ] || { echo "error: generated key/cert public keys differ"; exit 1; }

echo ""
echo "Done. Wrote:"
echo "  ${OUT_CERT}"
echo "  ${OUT_KEY}"
