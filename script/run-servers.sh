#!/bin/bash
#
#  Copyright (c) 2019, The OpenThread Registrar Authors.
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

# This script starts Registrar and MASA in the background.

set -e

# Select domain name
readonly DOMAIN_NAME=TestDomainTCE

# Select credentials
readonly CREDENTIAL_MASA=credentials/default_masa.p12
readonly CREDENTIAL_REGISTRAR=credentials/default_registrar.p12

TIMESTAMP=$(date "+%Y-%m-%d_%H.%M.%S")
readonly TIMESTAMP
readonly LOGS=logs/${TIMESTAMP}
readonly REGISTRAR_LOG=${LOGS}/registrar.log
readonly MASA_LOG=${LOGS}/masa.log

echo "Credentials file MASA set to     : ${CREDENTIAL_MASA}"
echo "Credentials file Registrar set to: ${CREDENTIAL_REGISTRAR}"
rm -rf "$LOGS"
mkdir -p "$LOGS"
echo "Log directory created            : ${LOGS}"

echo "starting Registrar server (CoAPS)..."
./script/run -registrar -v -d $DOMAIN_NAME -f ${CREDENTIAL_REGISTRAR} -p 5684 -m localhost:5685 \
    >> "${REGISTRAR_LOG}" 2>&1 &

echo "starting MASA server (HTTPS)..."
./script/run -masa -v -f ${CREDENTIAL_MASA} -p 5685 \
    >> "${MASA_LOG}" 2>&1 &

echo "Done"
