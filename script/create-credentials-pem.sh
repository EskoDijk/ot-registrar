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

# Build a new set of PEM certificates for a new vendor (MASA, Pledge) or a new
# customer (Registrar, Domain CA).

set -e

if [ $# -ne 1 ]; then
  echo "Usage: $0 <vendor>"
  echo "  Creates credentials/<vendor>/ and writes a set of PEM certificates/keys"
  echo "  for each role (pledge, registrar, masa) - for testing only."
  exit 1
fi

readonly VENDOR="$1"
readonly CRED_DIR="./credentials/${VENDOR}"
readonly OUT_DIR="${CRED_DIR}"
readonly GEN="./script/run --class com.google.openthread.tools.CredentialGenerator"

if [ -d "${CRED_DIR}" ]; then
  echo "error: vendor directory must be non-existent prior to creating: ${CRED_DIR}"
  exit 1
fi

echo "Building PEM certificates ..."
${GEN} -d "${VENDOR}"

# TODO check for success here

echo ""
echo "Done. Wrote PEM files to ${OUT_DIR}/."
echo "To packages these certs/keys into PKCS#12 (.p12) credentials files, use:"
echo "  ./script/create-credentials-p12.sh ${VENDOR}"
