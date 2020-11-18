#include <ctype.h>
#include <getopt.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <ecc.h>
#include <ecc_pointmul.h>
#include <ecdh_kat.h>
#include <ecdsa.h>
#include <utils.h>

#define HASH_NUM 4

static void strtolower(char *str);
static void ecc_pointmul2(EC_GROUP *group);
static void ecdh_kat2(EC_GROUP const *group);
static void ecdsa2(EC_GROUP const *group, const EVP_MD *(*hash)());

void strtolower(char *str) {
  while (*(str++)) {
    *str = (char)tolower(*str);
  }
}

void ecc_pointmul2(EC_GROUP *group) {
  Ecc_coord ecc_coord;

  int i;
  const char *array[ECC_POINTMUL_TEST_VECTOR_SIZE];
  char *tmp_x, *tmp_y;

  ecc_coord_k_values(array, group);
  ecc_coord_init(&ecc_coord);

  for (i = 0; i < ECC_POINTMUL_TEST_VECTOR_SIZE; i++) {
    ecc_pointmul(&ecc_coord, group, array[i]);

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

void ecdh_kat2(EC_GROUP const *group) {
  int i;
  Ecdh_parameters array[ECDH_KAT_TEST_VECTOR];
  char *p;

  ecdh_parameters_set_values(group, array);

  for (i = 0; i < ECDH_KAT_TEST_VECTOR; i++) {
    p = ecdh_kat(group, array[i].priv, array[i].kcx0, array[i].kcy0);

    fprintf(stdout, "Secret = 0x%s\n", array[i].priv);
    fprintf(stdout, "CounterKey = 04%s%s\n", array[i].kcx0, array[i].kcy0);
    fprintf(stdout, "K = %s\n\n", p);

    free(p);
  }
}

void ecdsa2(EC_GROUP const *group, const EVP_MD *(*hash)()) {
  int i;
  Ecdsa_parameters array[ECDSA_TEST_VECTOR];
  ECDSA_SIG *sign;
  char *tmp_r, *tmp_s;
  int dgst_len = 0;

  struct {
    const EVP_MD *(*key)();
    int element;
  } hm[HASH_NUM] = {
      {.key = &EVP_sha224, .element = SHA224_DIGEST_LENGTH},
      {.key = &EVP_sha256, .element = SHA256_DIGEST_LENGTH},
      {.key = &EVP_sha384, .element = SHA384_DIGEST_LENGTH},
      {.key = &EVP_sha512, .element = SHA512_DIGEST_LENGTH},
  };

  for (i = 0; i < HASH_NUM; i++) {
    if (hm[i].key == hash) {
      dgst_len = hm[i].element;
      break;
    }
  }

  ecdsa_parameters_set_values(group, dgst_len, array);

  for (i = 0; i < ECDSA_TEST_VECTOR; i++) {
    sign = ecdsa_deterministic_sign(group, hash, array[i].dgst,
                                    array[i].dgst_len, array[i].d, array[i].k);

    fprintf(stdout, "Msg = %s\n", array[i].dgst);
    fprintf(stdout, "X = 0x%s\n", array[i].d);
    fprintf(stdout, "Nonce  = %s\n", array[i].k);
    tmp_r = BN_bn2hex(sign->r);
    tmp_s = BN_bn2hex(sign->s);
    strtolower(tmp_r);
    strtolower(tmp_s);
    fprintf(stdout, "Signature = %s%s\n", tmp_r, tmp_s);

    if (tmp_r) {
      OPENSSL_free(tmp_r);
    }
    if (tmp_s) {
      OPENSSL_free(tmp_s);
    }
    if (sign) {
      ECDSA_SIG_free(sign);
    }
  }
}

int main(int argc, char **argv) {
  int i;
  int opt;
  EC_GROUP **ec_group = NULL;
  char *function;
  char *ec_name;
  char *hash_name;
  const EVP_MD *(*hash)();

  struct {
    char *key;
    EC_GROUP **element;
  } hm_ec[NUM_EC] = {
      {.key = "secp192r1", .element = &secp192r1},
      {.key = "secp224r1", .element = &secp224r1},
      {.key = "secp256r1", .element = &secp256r1},
      {.key = "secp384r1", .element = &secp384r1},
      {.key = "secp521r1", .element = &secp521r1},
      {.key = "frp256v1", .element = &frp256v1},
  };

  struct {
    char *key;
    const EVP_MD *(*element)();
  } hm_hash[HASH_NUM] = {
      {.key = "224", .element = &EVP_sha224},
      {.key = "256", .element = &EVP_sha256},
      {.key = "384", .element = &EVP_sha384},
      {.key = "512", .element = &EVP_sha512},
  };

  init_ecc();

  while ((opt = getopt(argc, argv, "e:f:h:")) != -1) {
    switch (opt) {
    case 'e':
      for (i = 0; i < NUM_EC; i++) {
        if (!strncmp(hm_ec[i].key, optarg, strlen(hm_ec[i].key))) {
          ec_name = hm_ec[i].key;
          ec_group = hm_ec[i].element;
          break;
        }
      }
      break;

    case 'f':
      function = optarg;

      if (strncmp("ecc_pointmul", function, 12) &&
          strncmp("ecdh", function, 4) && strncmp("ecdsa", function, 5)) {
        fprintf(stderr, "The function %s doesn't exist\n", function);

        exit(EXIT_FAILURE);
      }
      break;

    case 'h':
      if (strncmp("224", optarg, 3) &&
          strncmp("256", optarg, 3) &&
          strncmp("384", optarg, 3) &&
          strncmp("512", optarg, 3)) {
        fprintf(stderr, "The EVP_sha%s function doesn't exist\n", optarg);

        exit(EXIT_FAILURE);
      }
      for (i = 0; i < HASH_NUM; i++) {
        if (!strncmp(hm_hash[i].key, optarg, strlen(hm_hash[i].key))) {
          hash_name = hm_hash[i].key;
          hash = hm_hash[i].element;
          break;
        }
      }
      break;

    default:
      fprintf(stderr, "Usage: %s [-e] { secp192r1 | secp224r1 | secp256r1 | "
                      "secp384r1 | secp521r1 | frp256v1 } [-f] { ecc_pointmul "
                      "| ecdh | ecdsa } [-h] { 224 | 256 | 384 | 512 }\n",
              argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  if (!((getenv("OPENSSL_DEBUG_MEMORY") != NULL) &&
        (0 == strcmp(getenv("OPENSSL_DEBUG_MEMORY"), "off")))) {
    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
  } else {
    CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
  }
  CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
  ERR_load_crypto_strings();

  if (!strncmp("ecc_pointmul", function, 12)) {
    fprintf(stdout, "[%s]\n", ec_name);
    ecc_pointmul2(*ec_group);
  }

  else if (!strncmp("ecdh", function, 4)) {
    fprintf(stdout, "[%s]\n", ec_name);
    ecdh_kat2(*ec_group);
  }

  else if (!strncmp("ecdsa", function, 5)) {
    fprintf(stdout, "Group = %s\nHash = SHA-%s\n\n", ec_name, hash_name);
    ecdsa2(*ec_group, hash);
  }

  destroy_ecc();
  CRYPTO_cleanup_all_ex_data();
  ERR_remove_thread_state(NULL);
  ERR_free_strings();
  CRYPTO_mem_leaks_fp(stderr);

  return 0;
}
