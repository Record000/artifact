openssl x509 -in /home/szz/RPKI/REPO/ca_certificate.cer -inform DER -out /home/szz/RPKI/REPO/ca_certificate.pem
openssl x509 -in /home/szz/RPKI/REPO/ca_certificate/mft_ee.cer -inform DER -out /home/szz/RPKI/REPO/ca_certificate/mft_ee.pem
openssl verify -CAfile /home/szz/RPKI/REPO/ca_certificate.pem /home/szz/RPKI/REPO/ca_certificate/mft_ee.pem