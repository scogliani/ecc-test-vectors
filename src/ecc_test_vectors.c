#include <ctype.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <ecc.h>
#include <ecc_pointmul.h>
#include <ecdh_kat.h>
#include <ecdsa.h>
#include <utils.h>

void ecc_pointmul2(EC_GROUP const *group)
{
  Ecc_coord ecc_coord;

  int i;
  const char *array[ECC_POINTMUL_TEST_VECTOR_SIZE];
  char *tmp_x, *tmp_y;

  ecc_coord_k_values(array, group);
  ecc_coord_init(&ecc_coord);

  for (i = 0; i < ECC_POINTMUL_TEST_VECTOR_SIZE; i++)
  {
    ecc_pointmul(ecc_coord, group, array[i]);

    fprintf(stdout, "m = %s\n", array[i]);
    tmp_x = BN_bn2hex(ecc_coord.x);
    fprintf(stdout, "X = %s\n", tmp_x);
    tmp_y = BN_bn2hex(ecc_coord.y);
    fprintf(stdout, "Y = %s\n\n", tmp_y);

    OPENSSL_free(tmp_x);
    OPENSSL_free(tmp_y);
  }

  ecc_coord_destroy(&ecc_coord);
}

void ecdh_kat2(EC_GROUP const *group)
{
  int i;
  Ecdh_parameters array[ECDH_KAT_TEST_VECTOR];
  char *p;

  ecdh_parameters_set_values(group, array);

  for (i = 0; i < ECDH_KAT_TEST_VECTOR; i++)
  {
    p = ecdh_kat(group, array[i].priv, array[i].kcx0, array[i].kcy0);

    fprintf(stdout, "Secret = 0x%s\n", array[i].priv);
    fprintf(stdout, "CounterKey = 04%s%s\n", array[i].kcx0, array[i].kcy0);
    fprintf(stdout, "K = %s\n\n", p);

    free(p);
  }
}

void ecdsa2(EC_GROUP const *group, int dgst_len)
{
  int i;
  Ecdsa_parameters array[ECDSA_TEST_VECTOR];
  ECDSA_SIG *sign;
  char *tmp_r, *tmp_s;

  ecdsa_parameters_set_values(group, dgst_len, array);

  for (i = 0; i < ECDSA_TEST_VECTOR; i++)
  {
    sign = ecdsa_deterministic_sign(group, array[i].dgst, &EVP_sha224,
                                    array[i].d, array[i].k);

    fprintf(stdout, "Msg = %s\n", array[i].dgst);
    fprintf(stdout, "X = 0x%s\n", array[i].d);
    fprintf(stdout, "Nonce  = %s\n", array[i].k);
    tmp_r = BN_bn2hex(sign->r);
    tmp_s = BN_bn2hex(sign->s);
    fprintf(stdout, "r = %s\n", tmp_r);
    fprintf(stdout, "s = %s\n", tmp_s);

    if (tmp_r)
    {
      OPENSSL_free(tmp_r);
    }
    if (tmp_s)
    {
      OPENSSL_free(tmp_s);
    }
    if (sign)
    {
      ECDSA_SIG_free(sign);
    }
  }
}

int main(int argc, char **argv)
{
  if (argc != 2)
  {
    return -1;
  }

  init_ecc();

  if (!((getenv("OPENSSL_DEBUG_MEMORY") != NULL) &&
        (0 == strcmp(getenv("OPENSSL_DEBUG_MEMORY"), "off"))))
  {
    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
  }
  else
  {
    CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
  }
  CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
  ERR_load_crypto_strings();

  fprintf(stdout, "[%s]\n", argv[1]);

  if (!strncmp("secp192r1", argv[1], 9))
  {
#if defined(ECC_POINTMUL)
    ecc_pointmul2(secp192r1);
#elif defined(ECDH)
    ecdh_kat2(secp192r1);
#endif
  }
  else if (!strncmp("secp224r1", argv[1], 9))
  {
#if defined(ECC_POINTMUL)
    ecc_pointmul2(secp224r1);
#elif defined(ECDH)
    ecdh_kat2(secp224r1);
#elif defined(ECDSA)
    ecdsa2(secp224r1, SHA224_DIGEST_LENGTH);
    ecdsa2(secp224r1, SHA256_DIGEST_LENGTH);
    ecdsa2(secp224r1, SHA384_DIGEST_LENGTH);
    ecdsa2(secp224r1, SHA512_DIGEST_LENGTH);
#endif
  }
  else if (!strncmp("secp256r1", argv[1], 9))
  {
#if defined(ECC_POINTMUL)
    ecc_pointmul2(secp256r1);
#elif defined(ECDH)
    ecdh_kat2(secp256r1);
#endif
  }
  else if (!strncmp("secp384r1", argv[1], 9))
  {
#if defined(ECC_POINTMUL)
    ecc_pointmul2(secp384r1);
#elif defined(ECDH)
    ecdh_kat2(secp384r1);
#endif
  }
  else if (!strncmp("secp521r1", argv[1], 9))
  {
    ecc_pointmul2(secp521r1);
  }
  else if (!strncmp("frp256v1", argv[1], 8))
  {
#if defined(ECC_POINTMUL)
    ecc_pointmul2(frp256v1);
#elif defined(ECDH)
    ecdh_kat2(frp256v1);
#endif
  }

  destroy_ecc();
  CRYPTO_cleanup_all_ex_data();
  ERR_remove_thread_state(NULL);
  ERR_free_strings();
  CRYPTO_mem_leaks_fp(stderr);

  return 0;
}
