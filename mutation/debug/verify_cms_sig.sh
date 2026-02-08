#!/bin/bash

# CMS_FILE="/home/szz/RPKI/REPO/ca_certificate/manifest.mft"
# DER_CERT_FILE="/home/szz/RPKI/REPO/ca_certificate.cer"
CMS_FILE="/home/szz/RPKI/REPO/ca_certificate/manifest.mft"
DER_CERT_FILE="/home/szz/RPKI/REPO/ca_certificate.cer"

PEM_CERT_FILE="/home/szz/RPKI/REPO/ca_certificate.pem"

openssl x509 -inform DER -in "${DER_CERT_FILE}" -outform PEM -out "${PEM_CERT_FILE}"
if [ $? -ne 0 ]; then
  echo "Failed to convert DER certificate to PEM."
  exit 1
fi

openssl cms -verify -in "${CMS_FILE}" -CAfile "${PEM_CERT_FILE}" -inform DER -out verified_content.txt -outform PEM
if [ $? -eq 0 ]; then
  echo "CMS Signature verification successful."
else
  echo "CMS Signature verification failed."
fi
