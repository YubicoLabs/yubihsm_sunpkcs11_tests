#!/bin/bash

if [ "$#" -eq 1 ]; then
  BIN=$1 # path to the yubihsm-shell command line tool - using default connector
elif [ "$#" -gt 1 ]; then
  BIN="$1 -C $2" # path to the yubihsm-shell command line tool - using specified connector
else
  BIN="yubihsm-shell"
fi

run () {
  set +e
  $1 > output.txt 2>&1
  ret=$?
  if [ $ret -ne 0 ]; then
    echo $1
    cat output.txt
    rm output.txt
    exit 1
  else
    rm output.txt
  fi
  set -e
}

$BIN -p password -a sign-attestation-certificate -i 1 --attestation-id 0 2>&1 > /dev/null # Some YubiHSMs does not have default attestation certificate
default_attestation=$?


set -e

echo "====================== RSA keys ===================== "

keyid=1

RSA_KEYSIZES=("2048" "3072" "4096")

for k in ${RSA_KEYSIZES[@]}; do
  run "$BIN -p password -a put-asymmetric-key -i $keyid -l pkcs11_test_rsa$k -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate --in rsa$k.pem"
  echo "Import RSA$k key ... Done"
  run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_rsa$k-cert -A opaque-x509-certificate --informat=PEM --in rsa$k-cert.pem"
  echo "Import RSA$k certificate ... Done"
  keyid=$(($keyid + 1))
done


echo "====================== EC keys ===================== "

#EC_CURVES=("secp224r1" "secp256r1" "secp384r1" "secp521r1" "brainpool256r1" "brainpool384r1" "brainpool512r1")
EC_CURVES=("secp224r1" "secp256r1" "secp384r1" "secp521r1" "brainpoolP256r1" "brainpoolP384r1" "brainpoolP512r1")


for curve in ${EC_CURVES[@]}; do
  run "$BIN -p password -a put-asymmetric-key -i $keyid -l pkcs11_test_$curve -d 1 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate --in $curve.pem"
  echo "Import $curve key ... Done"
  run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_$curve-cert -A opaque-x509-certificate --informat=PEM --in $curve-cert.pem"
  echo "Import $curve certificate ... Done"
  keyid=$(($keyid + 1))
done

set +e