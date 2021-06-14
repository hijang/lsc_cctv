#ifndef CCTV_CRYPTO_H
#define CCTV_CRYPTO_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <glib.h>


int do_crypt_file(const char *src, const char *dest, int mode);
int do_crypt_buf(const char *path, unsigned char *buf, int *decrypted_size, int mode);
char* encrypt_filename(const char *filename);
char* decrypt_filename(const char *filename);

#endif // CCTV_CRYPTO_H
