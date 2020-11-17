#ifndef _ECC_POINTMUL_H__
#define _ECC_POINTMUL_H__

#include <openssl/ec.h>

/** Struct
 */
typedef struct {
    BIGNUM *x;
    BIGNUM *y;
} Ecc_coord;

#define ECC_POINTMUL_TEST_VECTOR_SIZE 52

/** Initialize an Ecc_coord object
 * @param ecc_coord Ecc_coord to initialize
 */
void ecc_coord_init(Ecc_coord *ecc_coord);

/** Destroy an Ecc_coord object
 * @param ecc_coord Ecc_coord to destroy
 */
void ecc_coord_destroy(Ecc_coord *ecc_coord);

/** Point multiplication Q = kP where P is the elliptic curve cryptography
 * @param ecc_coord The Q value (x, y)
 * @param group the P element from the point multiplication
 * @param k Element multiply to
 */
void ecc_pointmul(Ecc_coord *ecc_coord, EC_GROUP *group, const char *m);

/** Set k values to an array
 * @param array The array to set
 * @param group The k values from this specific group
 */
void ecc_coord_k_values(const char* array[ECC_POINTMUL_TEST_VECTOR_SIZE],
        EC_GROUP const *group);

#endif /* _ECC_POINTMUL_H__ */
