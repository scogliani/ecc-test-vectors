#include <openssl/err.h>

#include <create_ecc.h>

EC_GROUP *create_ecc(const char *kcp, const char *kca, const char *kcb,
                     const char *kcx0, const char *kcy0, const char *kcq,
                     const char *kci)
{
  EC_GROUP *group = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *p = NULL;
  BIGNUM *a = NULL;
  BIGNUM *b = NULL;
  BIGNUM *x0 = NULL;
  BIGNUM *y0 = NULL;
  BIGNUM *q = NULL;
  BIGNUM *i = NULL;
  EC_POINT *generator = NULL;

  if (!(ctx = BN_CTX_new()))
  {
    goto err;
  }

  if (!(p = BN_new()))
  {
    goto err;
  }

  if (!(a = BN_new()))
  {
    goto err;
  }

  if (!(b = BN_new()))
  {
    goto err;
  }

  if (!(q = BN_new()))
  {
    goto err;
  }

  if (!(x0 = BN_new()))
  {
    goto err;
  }

  if (!(y0 = BN_new()))
  {
    goto err;
  }

  if (!(i = BN_new()))
  {
    goto err;
  }

  if (!BN_hex2bn(&p, kcp))
  {
    goto err;
  }

  if (!BN_hex2bn(&a, kca))
  {
    goto err;
  }

  if (!BN_hex2bn(&b, kcb))
  {
    goto err;
  }

  if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL)
  {
    goto err;
  }

  if (!(generator = EC_POINT_new(group)))
  {
    goto err;
  }

  if (!BN_hex2bn(&x0, kcx0))
  {
    goto err;
  }

  if (!BN_hex2bn(&y0, kcy0))
  {
    goto err;
  }

  if (!EC_POINT_set_affine_coordinates_GFp(group, generator, x0, y0, ctx))
  {
    goto err;
  }

  if (EC_POINT_is_on_curve(group, generator, ctx) <= 0)
  {
    goto err;
  }

  if (!BN_hex2bn(&q, kcq))
  {
    goto err;
  }

  if (!BN_hex2bn(&i, kci))
  {
    goto err;
  }

  if (!EC_GROUP_set_generator(group, generator, q, i))
  {
    goto err;
  }

err:
  ERR_print_errors_fp(stderr);

  if (generator)
  {
    EC_POINT_free(generator);
  }

  if (i)
  {
    BN_free(i);
  }
  if (y0)
  {
    BN_free(y0);
  }

  if (x0)
  {
    BN_free(x0);
  }

  if (q)
  {
    BN_free(q);
  }

  if (b)
  {
    BN_free(b);
  }

  if (a)
  {
    BN_free(a);
  }

  if (p)
  {
    BN_free(p);
  }

  if (ctx)
  {
    BN_CTX_free(ctx);
  }

  return group;
}
