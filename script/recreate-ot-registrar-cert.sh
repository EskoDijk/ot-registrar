#!/bin/bash
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