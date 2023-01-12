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
echo "pkcs11_test_rsa2048...."
run_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l pkcs11_test_rsa2048 -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate --in rsa_2048.pem"
keyid=$(tail -1 resp.txt | awk '{print $4}')
set +e
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 2>&1 > /dev/null # Some YubiHSMs does not have default attestation certificate
default_attestation=$?
set -e
if [ $default_attestation -eq 0 ]; then
  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
  run "rm cert.pem"
else
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
fi
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_rsa2048_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm selfsigned_cert.pem"
echo "pkcs11_test_rsa2048.... DONE"

echo "pkcs11_test_rsa3072...."
run_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l pkcs11_test_rsa3072 -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate --in rsa_3072.pem"
keyid=$(tail -1 resp.txt | awk '{print $4}')
if [ $default_attestation -eq 0 ]; then
  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
  run "rm cert.pem"
else
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
fi
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_rsa3072_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm selfsigned_cert.pem"
echo "pkcs11_test_rsa3072.... DONE"

echo "pkcs11_test_rsa4096...."
run_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l pkcs11_test_rsa4096 -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate --in rsa_4096.pem"
keyid=$(tail -1 resp.txt | awk '{print $4}')
if [ $default_attestation -eq 0 ]; then
  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
  run "rm cert.pem"
else
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
fi
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_rsa4096_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm selfsigned_cert.pem"
echo "pkcs11_test_rsa4096.... DONE"

echo "====================== EC keys ===================== "
#echo "pkcs11_test_ecp224...."
#run_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l pkcs11_test_ecp224 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate --in secp224r1.pem"
#keyid=$(tail -1 resp.txt | awk '{print $4}')
#if [ $default_attestation -eq 0 ]; then
#  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
#  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
#  run "rm cert.pem"
#else
#  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
#fi
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
#run "$BIN -p password -a delete-object -i $keyid -t opaque"
#run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecp224_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
#run "rm selfsigned_cert.pem"
#echo "pkcs11_test_ecp224.... DONE"

echo "pkcs11_test_ecp256...."
run_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l pkcs11_test_ecp256 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate --in secp256r1.pem"
keyid=$(tail -1 resp.txt | awk '{print $4}')
if [ $default_attestation -eq 0 ]; then
  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
  run "rm cert.pem"
else
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
fi
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecp256_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm selfsigned_cert.pem"
echo "pkcs11_test_ecp256.... DONE"

echo "pkcs11_test_ecp384...."
run_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l pkcs11_test_ecp384 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate --in secp384r1.pem"
keyid=$(tail -1 resp.txt | awk '{print $4}')
if [ $default_attestation -eq 0 ]; then
  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
  run "rm cert.pem"
else
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
fi
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecp384_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm selfsigned_cert.pem"
echo "pkcs11_test_ecp384.... DONE"

echo "pkcs11_test_ecp521...."
run_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l pkcs11_test_ecp521 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate --in secp521r1.pem"
keyid=$(tail -1 resp.txt | awk '{print $4}')
if [ $default_attestation -eq 0 ]; then
  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
  run "rm cert.pem"
else
  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
fi
run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
run "$BIN -p password -a delete-object -i $keyid -t opaque"
run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecp521_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
run "rm selfsigned_cert.pem"
echo "pkcs11_test_ecp521.... DONE"

#echo "pkcs11_test_eck256...."
#run_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l pkcs11_test_eck256 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A eck256"
#keyid=$(tail -1 resp.txt | awk '{print $4}')
#if [ $default_attestation -eq 0 ]; then
#  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
#  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
#  run "rm cert.pem"
#else
#  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
#fi
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
#run "$BIN -p password -a delete-object -i $keyid -t opaque"
#run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_eck256_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
#run "rm selfsigned_cert.pem"
#echo "pkcs11_test_eck256.... DONE"

#echo "pkcs11_test_ecbp256...."
#run_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l pkcs11_test_ecbp256 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate --in brainpool256r1.pem"
#keyid=$(tail -1 resp.txt | awk '{print $4}')
#if [ $default_attestation -eq 0 ]; then
#  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
#  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
#  run "rm cert.pem"
#else
#  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
#fi
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
#run "$BIN -p password -a delete-object -i $keyid -t opaque"
#run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecbp256_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
#run "rm selfsigned_cert.pem"
#echo "pkcs11_test_ecbp256.... DONE"
#
#echo "pkcs11_test_ecbp384...."
#run_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l pkcs11_test_ecbp384 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate --in brainpool384r1.pem"
#keyid=$(tail -1 resp.txt | awk '{print $4}')
#if [ $default_attestation -eq 0 ]; then
#  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
#  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
#  run "rm cert.pem"
#else
#  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
#fi
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
#run "$BIN -p password -a delete-object -i $keyid -t opaque"
#run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecbp384_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
#run "rm selfsigned_cert.pem"
#echo "pkcs11_test_ecbp384.... DONE"
#
#echo "pkcs11_test_ecbp512...."
#run_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l pkcs11_test_ecbp512 -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate --in brainpool512r1.pem"
#keyid=$(tail -1 resp.txt | awk '{print $4}')
#if [ $default_attestation -eq 0 ]; then
#  run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem"
#  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in cert.pem"
#  run "rm cert.pem"
#else
#  run "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --informat=PEM --in x509template.pem"
#fi
#run "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem"
#run "$BIN -p password -a delete-object -i $keyid -t opaque"
#run "$BIN -p password -a put-opaque -i $keyid -l pkcs11_test_ecbp512_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem"
#run "rm selfsigned_cert.pem"
#echo "pkcs11_test_ecbp512.... DONE"

set +e