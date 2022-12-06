 #!/bin/bash
 CREDS=./credentials/ietf-draft-constrained-brski
 echo "Creating .p12 keystore file for credentials in $CREDS ..."
 java -cp target/ot-registrar-0.1-SNAPSHOT-jar-with-dependencies.jar com.google.openthread.tools.CredentialGenerator \
              -c $CREDS/domain_ca.pem $CREDS/privkey_domain_ca.pem \
              -r $CREDS/registrar.pem $CREDS/privkey_registrar.pem \
              -m $CREDS/masa_ca.pem $CREDS/privkey_masa_ca.pem \
              -p $CREDS/pledge.pem $CREDS/privkey_pledge.pem \
              -o ./credentials/keystore_ietf-draft-constrained-brski.p12