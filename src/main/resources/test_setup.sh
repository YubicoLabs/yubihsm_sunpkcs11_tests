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

run_with_resp () {
  set +e
  $1 > resp.txt 2>&1
  ret=$?
  if [ $ret -ne 0 ]; then
    echo $1
    cat resp.txt
    rm resp.txt
    exit 1
  fi
  set -e
}

set -e

echo "====================== RSA keys ===================== "
echo "RSA2048...."
run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_rsa2048 -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate -A rsa2048"
keyid=$(tail -1 resp.txt | awk '{print $4}')
set +e
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 2>&1 > /dev/null # Some YubiHSMs does not have default attestation certificate
skip_attestation=$?
set -e
if [ $skip_attestation -ne 0 ]; then
  exit
fi
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
run "openssl x509 -in cert.pem -out cert.der -outform DER"
run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_rsa2048_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm cert.pem cert.der selfsigned_cert.pem"
echo "RSA2048.... DONE"

echo "RSA3072...."
run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_rsa3072 -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate -A rsa3072"
keyid=$(tail -1 resp.txt | awk '{print $4}')
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
run "openssl x509 -in cert.pem -out cert.der -outform DER"
run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_rsa3072_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm cert.pem cert.der selfsigned_cert.pem"
echo "RSA3072.... DONE"

echo "RSA4096...."
run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_rsa4096 -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate -A rsa4096"
keyid=$(tail -1 resp.txt | awk '{print $4}')
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
run "openssl x509 -in cert.pem -out cert.der -outform DER"
run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_rsa4096_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm cert.pem cert.der selfsigned_cert.pem"
echo "RSA4096.... DONE"

echo "====================== EC keys ===================== "
#echo "ECP224...."
#run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_ecp224 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp224"
#keyid=$(tail -1 resp.txt | awk '{print $4}')
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
#run "openssl x509 -in cert.pem -out cert.der -outform DER"
#run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
#run "$BIN -p password -a delete-object -i $keyid -t opaque"
#run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecp224_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
#run "rm cert.pem cert.der selfsigned_cert.pem"
#echo "ECP224.... DONE"

echo "ECP256...."
run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_ecp256 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp256"
keyid=$(tail -1 resp.txt | awk '{print $4}')
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
run "openssl x509 -in cert.pem -out cert.der -outform DER"
run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecp256_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm cert.pem cert.der selfsigned_cert.pem"
echo "ECP256.... DONE"

echo "ECP384...."
run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_ecp384 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp384"
keyid=$(tail -1 resp.txt | awk '{print $4}')
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
run "openssl x509 -in cert.pem -out cert.der -outform DER"
run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecp384_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm cert.pem cert.der selfsigned_cert.pem"
echo "ECP384.... DONE"

echo "ECP521...."
run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_ecp521 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp521"
keyid=$(tail -1 resp.txt | awk '{print $4}')
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
run "openssl x509 -in cert.pem -out cert.der -outform DER"
run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecp521_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm cert.pem cert.der selfsigned_cert.pem"
echo "ECP521.... DONE"

#echo "ECK256...."
#run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_eck256 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A eck256"
#keyid=$(tail -1 resp.txt | awk '{print $4}')
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
#run "openssl x509 -in cert.pem -out cert.der -outform DER"
#run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
#run "$BIN -p password -a delete-object -i $keyid -t opaque"
#run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_eck256_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
#run "rm cert.pem cert.der selfsigned_cert.pem"
#echo "ECK256.... DONE"

#echo "Brainpool256...."
#run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_ecbp256 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecbp256"
#keyid=$(tail -1 resp.txt | awk '{print $4}')
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
#run "openssl x509 -in cert.pem -out cert.der -outform DER"
#run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
#run "$BIN -p password -a delete-object -i $keyid -t opaque"
#run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecbp256_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
#run "rm cert.pem cert.der selfsigned_cert.pem"
#echo "Brainpool256.... DONE"
#
#echo "Brainpool384...."
#run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_ecbp384 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecbp384"
#keyid=$(tail -1 resp.txt | awk '{print $4}')
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
#run "openssl x509 -in cert.pem -out cert.der -outform DER"
#run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
#run "$BIN -p password -a delete-object -i $keyid -t opaque"
#run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecbp384_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
#run "rm cert.pem cert.der selfsigned_cert.pem"
#echo "Brainpool384.... DONE"
#
#echo "Brainpool512...."
#run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_ecbp512 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecbp512"
#keyid=$(tail -1 resp.txt | awk '{print $4}')
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
#run "openssl x509 -in cert.pem -out cert.der -outform DER"
#run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der"
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
#run "$BIN -p password -a delete-object -i $keyid -t opaque"
#run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecbp512_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
#run "rm cert.pem cert.der selfsigned_cert.pem"
#echo "Brainpool512.... DONE"

set +e