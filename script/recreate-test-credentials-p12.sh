#!/bin/bash
#
#  Copyright (c) 2021, The OpenThread Registrar Authors.
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

readonly JAR_FILE=./target/ot-registrar-0.1-SNAPSHOT-jar-with-dependencies.jar
readonly CREDENTIAL=./credentials/local-masa/test_credentials.p12
readonly CRED_DIR=./credentials/local-masa

# test if build JAR exists
if [ ! -f  "${JAR_FILE}" ]; then
  echo "Please build using 'mvn -DskipTests package' before running; and run this script from base directory of repo."
  exit 1
fi

java -cp $JAR_FILE com.google.openthread.tools.CredentialGenerator -c $CRED_DIR/domainca_cert.pem $CRED_DIR/domainca_private.pem -m $CRED_DIR/masa_cert.pem $CRED_DIR/masa_private.pem -r $CRED_DIR/registrar_cert.pem $CRED_DIR/registrar_private.pem -o $CREDENTIAL