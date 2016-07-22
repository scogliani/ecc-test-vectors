#include <create_ecc.h>
#include <utils.h>

#include <openssl/err.h>

EC_GROUP* create_ecc(const char* kcp,
                     const char* kca,
                     const char* kcb,
                     const char* kcx0,
                     const char* kcy0,
                     const char* kcq,
                     const char* kci)
{
  EC_GROUP* group;
  BN_CTX* ctx;
  BIGNUM* p;
  BIGNUM* a;
  BIGNUM* b;
  BIGNUM* x0;
  BIGNUM* y0;
  BIGNUM* q;
  BIGNUM* i;
  EC_POINT* generator;

  ctx = BN_CTX_new();
  if (!ctx)
    ABORT;

  p = BN_new();
  a = BN_new();
  b = BN_new();
  x0 = BN_new();
  y0 = BN_new();
  q = BN_new();
  i = BN_new();

  if (!p || !a || !b || !x0 || !y0 || !q)
    ABORT;

  if (!BN_hex2bn(&p, kcp))
    ABORT;
  if (!BN_hex2bn(&a, kca))
    ABORT;
  if (!BN_hex2bn(&b, kcb))
    ABORT;
  if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL)
    ABORT;

  generator = EC_POINT_new(group);

  if (!generator)
    ABORT;

  if (!BN_hex2bn(&x0, kcx0))
    ABORT;
  if (!BN_hex2bn(&y0, kcy0))
    ABORT;
  if (!EC_POINT_set_affine_coordinates_GFp(group, generator, x0, y0, ctx))
    ABORT;
  if (EC_POINT_is_on_curve(group, generator, ctx) <= 0)
    ABORT;
  if (!BN_hex2bn(&q, kcq))
    ABORT;
  if (!BN_hex2bn(&i, kci))
    ABORT;
  if (!EC_GROUP_set_generator(group, generator, q, i))
    ABORT;

  EC_POINT_free(generator);
  BN_free(i);
  BN_free(y0);
  BN_free(x0);
  BN_free(q);
  BN_free(p);
  BN_free(b);
  BN_free(a);
  BN_CTX_free(ctx);

  return group;
}
