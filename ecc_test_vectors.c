#include <create_ecc.h>
#include <ecc_pointmul.h>

#include <openssl/err.h>

#include <string.h>

int main()
{
  EC_GROUP* secp192r1 =
      create_ecc("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
                 "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
                 "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
                 "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
                 "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
                 "01");

  EC_GROUP* frp256v1 =
      create_ecc("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03",
                 "F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00",
                 "EE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F",
                 "B6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF",
                 "6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB",
                 "F1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1",
                 "01");

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

  fprintf(stdout, "[secp192r1]\n");
  ecc_pointmul(secp192r1);

  fprintf(stdout, "[frp256v1]\n");
  ecc_pointmul(frp256v1);

  EC_GROUP_free(frp256v1);
  EC_GROUP_free(secp192r1);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  ERR_remove_thread_state(NULL);
  CRYPTO_mem_leaks_fp(stderr);

  return 0;
}
