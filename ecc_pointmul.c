#include <create_ecc.h>
#include <ecc_pointmul.h>
#include <utils.h>

#include <openssl/err.h>

void ecc_pointmul(EC_GROUP const* group)
{
#define ECC_POINTMUL_TEST_VECTOR_SIZE 52
  int i;
  const char* array[ECC_POINTMUL_TEST_VECTOR_SIZE] = {
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "7",
      "8",
      "9",
      "10",
      "11",
      "12",
      "13",
      "14",
      "15",
      "16",
      "17",
      "18",
      "19",
      "20",
      "112233445566778899",
      "112233445566778899112233445566778899",
      "176980527797516303525377593084236712909374178672537678600734933265332381"
      "265665829141343503325767757909536663252144885414127592614418729449986393"
      "3403633025023",
      "104748400337157462316262627929132596317243790506798133267698218707528750"
      "292682889221414310155907963824712114916552440160880550666043997030661040"
      "721887239",
      "670390386507834588814138165143016803949666407735096505428813312654930705"
      "874178867114819742977734393646612757593803178614740947262747970246988421"
      "4509568000",
      "167592564368239530540451716564356225188002695878089653169885673702417988"
      "034333987833638241205026343194297493964668348090643463296347825763975734"
      "1102436352",
      "127851333821494152214024952025867017986206961694467725990382357218623386"
      "921901561639515589638569590592323816028647439244274517867695151543968107"
      "06943",
      "214524875832249255872206855495734426889477529336261655255492425273322727"
      "861341825677722947375406711676372335314043071600934941615185418540320233"
      "184489636351",
      "511404862755678591311390778908355268846484618578230883486511538405082876"
      "213668545068312447465312722466202951231042695658670559493782663956047687"
      "84399",
      "665152971602520688103527995288152062784115224721278452091442503931260612"
      "019887908083964331134716901924908019823940835656341344740227044546210206"
      "8592377843",
      "322455182461323223253768007794681866015683528877808734480537039781137973"
      "163167125485384682668227367787021477846223717136514039018377022685332936"
      "3961324241919",
      "124866131284428854303808740439912850802549174883962849538151492513154126"
      "006345815390666630922976120406699780176235877528454096531672770218641326"
      "08",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005429",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005430",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005431",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005432",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005433",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005434",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005435",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005436",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005437",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005438",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005439",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005440",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005441",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005442",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005443",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005444",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005445",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005446",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "8892707005447",
      "686479766013060971498190079908139321726943530014330540939446345918554318"
      "339765539424505774633321719753296399637136332111386476861244038034037280"
      "88927070054485023"};

  BN_CTX* ctx;
  BIGNUM* x;
  BIGNUM* y;
  BIGNUM* x_get;
  BIGNUM* y_get;
  BIGNUM* mul;
  EC_POINT* point;

  x = BN_new();
  y = BN_new();
  x_get = BN_new();
  y_get = BN_new();
  mul = BN_new();

  if (!x || !y || !x_get || !y_get || !mul)
    ABORT;

  ctx = BN_CTX_new();
  if (!ctx)
    ABORT;

  point = EC_POINT_new(group);

  if (!point)
    ABORT;

  for (i = 0; i < ECC_POINTMUL_TEST_VECTOR_SIZE; i++)
  {
    if (!BN_dec2bn(&mul, array[i]))
      ABORT;

    if (!EC_POINT_mul(group, point, mul, NULL, NULL, ctx))
      ABORT;

    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x_get, y_get, ctx))
      ABORT;

    fprintf(stdout, "m = %s\n", array[i]);
    fprintf(stdout, "X = 0x");
    BN_print_fp(stdout, x_get);
    fprintf(stdout, "\nY = 0x");
    BN_print_fp(stdout, y_get);
    fprintf(stdout, "\n\n");
  }

  EC_POINT_free(point);
  BN_free(mul);
  BN_free(y_get);
  BN_free(x_get);
  BN_free(y);
  BN_free(x);
  BN_CTX_free(ctx);
}
