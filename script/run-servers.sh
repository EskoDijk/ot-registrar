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

# This script starts an entire set of Registrar and MASA in the background.

set -e

# Select domain name
readonly DOMAIN_NAME=TestDomainTCE

# Select credentials
#readonly CREDENTIAL=credentials/threadgroup-5f9d307c.p12
#readonly CREDENTIAL=credentials/local-masa/test_credentials.p12
readonly CREDENTIAL=credentials/iotconsultancy-masa/credentials.p12

readonly TIMESTAMP=$(date "+%Y-%m-%d_%H.%M.%S")
readonly LOGS=logs/${TIMESTAMP}
readonly REGISTRAR_LOG=${LOGS}/registrar.log
readonly MASA_LOG=${LOGS}/masa.log

echo "Credentials file set to: ${CREDENTIAL}"
rm -rf $LOGS
mkdir -p $LOGS

echo "starting Registrar server (CoAPS), log=${REGISTRAR_LOG}..."
./script/run -registrar -v -d $DOMAIN_NAME -f $CREDENTIAL -m localhost:9994 \
    >> $REGISTRAR_LOG 2>&1 &

echo "starting MASA server (HTTPS), log=${MASA_LOG}..."
./script/run -masa -v -f $CREDENTIAL \
    >> $MASA_LOG 2>&1 &

echo "Done"
