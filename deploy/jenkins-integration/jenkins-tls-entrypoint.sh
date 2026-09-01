#!/usr/bin/env bash
set -euo pipefail

root_keystore=/var/jenkins_home/tls/root.p12
root_certificate=/var/jenkins_home/tls/ca.crt
keystore=/var/jenkins_home/tls/jenkins.p12
request=/var/jenkins_home/tls/jenkins.csr
certificate=/var/jenkins_home/tls/jenkins.crt
mkdir -p "$(dirname "$keystore")"

if [[ ! -s "$keystore" || ! -s "$root_certificate" ]]; then
  rm -f "$root_keystore" "$root_certificate" "$keystore" "$request" "$certificate"
  keytool -genkeypair -noprompt \
    -alias synapse-jenkins-root \
    -keyalg RSA \
    -keysize 2048 \
    -validity 30 \
    -storetype PKCS12 \
    -keystore "$root_keystore" \
    -storepass "$JENKINS_HTTPS_KEYSTORE_PASSWORD" \
    -keypass "$JENKINS_HTTPS_KEYSTORE_PASSWORD" \
    -dname 'CN=Synapse Jenkins E2E CA' \
    -ext 'BC=ca:true' \
    -ext 'KU=keyCertSign,cRLSign'
  keytool -exportcert -rfc \
    -alias synapse-jenkins-root \
    -keystore "$root_keystore" \
    -storepass "$JENKINS_HTTPS_KEYSTORE_PASSWORD" \
    -file "$root_certificate"

  keytool -genkeypair -noprompt \
    -alias jenkins \
    -keyalg RSA \
    -keysize 2048 \
    -validity 30 \
    -storetype PKCS12 \
    -keystore "$keystore" \
    -storepass "$JENKINS_HTTPS_KEYSTORE_PASSWORD" \
    -keypass "$JENKINS_HTTPS_KEYSTORE_PASSWORD" \
    -dname 'CN=jenkins' \
    -ext 'SAN=dns:jenkins,dns:localhost,ip:127.0.0.1'
  keytool -certreq \
    -alias jenkins \
    -keystore "$keystore" \
    -storepass "$JENKINS_HTTPS_KEYSTORE_PASSWORD" \
    -file "$request"
  keytool -gencert -rfc \
    -alias synapse-jenkins-root \
    -keystore "$root_keystore" \
    -storepass "$JENKINS_HTTPS_KEYSTORE_PASSWORD" \
    -infile "$request" \
    -validity 30 \
    -ext 'BC=ca:false' \
    -ext 'KU=digitalSignature,keyEncipherment' \
    -ext 'EKU=serverAuth' \
    -ext 'SAN=dns:jenkins,dns:localhost,ip:127.0.0.1' \
    -outfile "$certificate"
  keytool -importcert -noprompt \
    -alias synapse-jenkins-root \
    -keystore "$keystore" \
    -storepass "$JENKINS_HTTPS_KEYSTORE_PASSWORD" \
    -file "$root_certificate"
  keytool -importcert -noprompt \
    -alias jenkins \
    -keystore "$keystore" \
    -storepass "$JENKINS_HTTPS_KEYSTORE_PASSWORD" \
    -file "$certificate"
  rm -f "$request" "$certificate"
fi

exec /usr/bin/tini -- /usr/local/bin/jenkins.sh \
  --httpPort=-1 \
  --httpsPort=8443 \
  --httpsKeyStore="$keystore" \
  --httpsKeyStorePassword="$JENKINS_HTTPS_KEYSTORE_PASSWORD"
