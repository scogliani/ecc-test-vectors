#include <openssl/bn.h>
#include <openssl/ecdh.h>

#include <ecdh_kat.h>
#include <mk_eckey.h>
#include <utils.h>

void ecdh_kat(EC_GROUP* group,
              const char* priv,
              const char* kcx0,
              const char* kcy0)
{
  EC_KEY* key = NULL;
  size_t Ztmplen;
  BIGNUM* x0;
  BIGNUM* y0;
  EC_POINT* pub;
  BN_CTX* ctx;
  unsigned char* Ztmp = NULL;
  char* p;

  ctx = BN_CTX_new();
  if (!ctx)
    ABORT;

  key = mk_eckey(group, priv);
  if (!key)
    ABORT;
  /************************/
  x0 = BN_new();
  y0 = BN_new();

  if (!x0 || !y0)
    ABORT;

  if (!BN_hex2bn(&x0, kcx0))
    ABORT;

  if (!BN_hex2bn(&y0, kcy0))
    ABORT;

  if (!(pub = EC_POINT_new(group)))
    ABORT;

  if (!EC_POINT_set_affine_coordinates_GFp(group, pub, x0, y0, ctx))
    ABORT;
  /************************/

  Ztmplen = (size_t)(EC_GROUP_get_degree(EC_KEY_get0_group(key)) + 7) / 8;

  Ztmp = OPENSSL_malloc(Ztmplen);

  if (!ECDH_compute_key(Ztmp, Ztmplen, pub, key, 0))
    ABORT;

  p = pt(Ztmp, Ztmplen);
  fprintf(stdout, "Secret = 0x%s\n", priv);
  fprintf(stdout, "CounterKey = %s%s\n", kcx0, kcy0);
  fprintf(stdout, "K = %s\n\n", p);

  free(p);
  BN_CTX_free(ctx);
  EC_POINT_free(pub);
  BN_free(y0);
  BN_free(x0);
  OPENSSL_free(Ztmp);
  EC_KEY_free(key);
}

