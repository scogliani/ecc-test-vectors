# Elliptic curves cryptography test vectors

Elliptic curves cryptography program for checking point multiplication, ECDH and ECDSA.
The output is based on test vectors from [Botan project](https://github.com/randombit/botan)

For the moment, it is POSIX dependant (getopt usage)

## Elliptic curves cryptography point multiplication

Test vectors references are available here: http://point-at-infinity.org/ecc/nisttv

## ECDSA Signature Generation Component test vectors

Test vectors references are available here: http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip

## ECCCDH Primitive test vectors

Test vectors references are available here: http://csrc.nist.gov/groups/STM/cavp/documents/components/ecccdhtestvectors.zip

## Parameters

This experimental test vectors generator uses openssl-1.0.2h

## What is needed?

- CMake
- A C compiler (gcc, clang, ...)
- AddressSanitizer

## Compilation

- cmake .

## Usage

`./ecc_test_vectors [-e] { secp192r1 | secp224r1 | secp256r1 | secp384r1 | secp521r1 | frp256v1 } [-f] { ecc_pointmul | ecdh | ecdsa } [-h] { 224 | 256 | 384 | 512 }`

-e
  Specify the elliptic curve cryptography

-f
  Specify the function

-h
  Specify the sha hash function (sha224, sha256, sha384 or sha512)
