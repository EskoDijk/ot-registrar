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

# Build per-role PKCS#12 keystores for a vendor from PEM cert/key files using a
# uniform naming scheme. For each role whose files are present in
# credentials/<vendor>/, writes credentials/<vendor>_<role>.p12 containing only
# the aliases that role loads at runtime.
#
# Expected files in credentials/<vendor>/ (standard naming; certificate is
# <name>.pem, its private key is privkey_<name>.pem):
#
#   pledge    : pledge.pem  privkey_pledge.pem  masa_ca.pem
#   registrar : registrar.pem privkey_registrar.pem  domain_ca.pem privkey_domain_ca.pem
#   masa      : masa.pem    privkey_masa.pem    masa_ca.pem privkey_masa_ca.pem
#
# Output keystores use password 'OpenThread'. Copy the result onto the runtime
# default for a role to use it, e.g.:
#   cp credentials/honeydukes_pledge.p12 credentials/default_pledge.p12

set -e

if [ $# -ne 1 ]; then
  echo "Usage: $0 <vendor>"
  echo "  Reads credentials/<vendor>/ and writes credentials/<vendor>_<role>.p12 for"
  echo "  each role (pledge, registrar, masa) whose PEM files are present."
  exit 1
fi

readonly VENDOR="$1"
readonly CRED_DIR="./credentials/${VENDOR}"
readonly OUT_DIR="./credentials"
readonly GEN="./script/lib/helper-cp-run.sh com.google.openthread.tools.CredentialGenerator"

if [ ! -d "${CRED_DIR}" ]; then
  echo "error: vendor directory not found: ${CRED_DIR}"
  exit 1
fi

made=0

# Pledge: pledge cert+key, and the MASA CA as trust anchor (no key needed).
if [ -f "${CRED_DIR}/pledge.pem" ] && [ -f "${CRED_DIR}/privkey_pledge.pem" ] \
    && [ -f "${CRED_DIR}/masa_ca.pem" ]; then
  echo "Building ${VENDOR}_pledge.p12 ..."
  ${GEN} -role pledge \
      -p "${CRED_DIR}/pledge.pem" "${CRED_DIR}/privkey_pledge.pem" \
      -m "${CRED_DIR}/masa_ca.pem" \
      -o "${OUT_DIR}/${VENDOR}_pledge.p12"
  made=$((made + 1))
fi

# Registrar: registrar cert+key chained to the domain CA (which needs its key).
if [ -f "${CRED_DIR}/registrar.pem" ] && [ -f "${CRED_DIR}/privkey_registrar.pem" ] \
    && [ -f "${CRED_DIR}/domain_ca.pem" ] && [ -f "${CRED_DIR}/privkey_domain_ca.pem" ]; then
  echo "Building ${VENDOR}_registrar.p12 ..."
  ${GEN} -role registrar \
      -r "${CRED_DIR}/registrar.pem" "${CRED_DIR}/privkey_registrar.pem" \
      -c "${CRED_DIR}/domain_ca.pem" "${CRED_DIR}/privkey_domain_ca.pem" \
      -o "${OUT_DIR}/${VENDOR}_registrar.p12"
  made=$((made + 1))
fi

# MASA: masa server cert+key chained to the MASA CA (which needs its key).
if [ -f "${CRED_DIR}/masa.pem" ] && [ -f "${CRED_DIR}/privkey_masa.pem" ] \
    && [ -f "${CRED_DIR}/masa_ca.pem" ] && [ -f "${CRED_DIR}/privkey_masa_ca.pem" ]; then
  echo "Building ${VENDOR}_masa.p12 ..."
  ${GEN} -role masa \
      -ms "${CRED_DIR}/masa.pem" "${CRED_DIR}/privkey_masa.pem" \
      -m "${CRED_DIR}/masa_ca.pem" "${CRED_DIR}/privkey_masa_ca.pem" \
      -o "${OUT_DIR}/${VENDOR}_masa.p12"
  made=$((made + 1))
fi

if [ "${made}" -eq 0 ]; then
  echo "error: no complete role credential set found in ${CRED_DIR} using the standard naming."
  echo "  pledge    needs: pledge.pem privkey_pledge.pem masa_ca.pem"
  echo "  registrar needs: registrar.pem privkey_registrar.pem domain_ca.pem privkey_domain_ca.pem"
  echo "  masa      needs: masa.pem privkey_masa.pem masa_ca.pem privkey_masa_ca.pem"
  exit 1
fi

echo ""
echo "Done. Wrote ${made} keystore(s) to ${OUT_DIR}/."
echo "To use one as a runtime default, copy it onto the role's default_*.p12, e.g.:"
echo "  cp ${OUT_DIR}/${VENDOR}_pledge.p12 ${OUT_DIR}/default_pledge.p12"
