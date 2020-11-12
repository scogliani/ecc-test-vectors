#ifndef _MK_ECKEY_H__
#define _MK_ECKEY_H__


EC_KEY *mk_eckey(EC_GROUP const *group, const char *private_key,
                               const char *x, const char *y);

#endif /* _MK_ECKEY_H__ */
