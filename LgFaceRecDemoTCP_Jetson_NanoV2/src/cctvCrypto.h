#ifndef CCTV_CRYPTO_H
#define CCTV_CRYPTO_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


int do_crypt_file(const char *src, const char *dest, int mode);
int do_crypt_buf(const char *path, unsigned char *buf, int *decrypted_size, int mode);

#endif // CCTV_CRYPTO_H
