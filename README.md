# Elliptic curves cryptography test vectors

Elliptic curves cryptography program for checking point multiplication, ECDH and ECDSA.
For the moment, it only works on GFp and ECDH and ECDSA is not implemented yet.

## Elliptic curves cryptography point multiplication

Test vectors references are available here: http://point-at-infinity.org/ecc/nisttv

## ECDSA Signature Generation Component test vectors

Test vectors references are available here: http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip

## ECCCDH Primitive test vectors

Test vectors references are available here: http://csrc.nist.gov/groups/STM/cavp/documents/components/ecccdhtestvectors.zip

## Parameters

This experimental test vectors generator uses openssl-1.0.2h

## Compilation

- You need first to download and build the openssl source code
- Then make
- And ./ecc_test_vectors

## Parameters

You can specify in compilation time ECDH or ECC_POINTMUL
