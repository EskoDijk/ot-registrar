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

# Recreate the cert for: OT Registrar (RA)
# signed by root=domainCA

if [ -d "./credentials/local-masa" ]
then
  cd ./credentials/local-masa
else
  echo "Please run script from base directory of this repo."
  exit 1
fi

# days certificate is valid
VALIDITY=1825

echo "--- Creating new Registrar RA certificate as './credentials/local-masa/registrar_cert2.pem'"

# create csr
openssl req -new -key registrar_private.pem -out temp.csr -subj "/CN=registrar/OU=OpenThread/O=Google/L=SH/C=CN"

# sign csr
# note: serial no is set manually.
openssl x509 -req -in temp.csr -extfile ./x509v3_registrar.ext -CA domainca_cert.pem -CAkey domainca_private.pem -set_serial 3 -out registrar_cert2.pem -days $VALIDITY -sha256

# cleanup temp file
rm temp.csr

# show it
openssl x509 -text -noout -in registrar_cert2.pem