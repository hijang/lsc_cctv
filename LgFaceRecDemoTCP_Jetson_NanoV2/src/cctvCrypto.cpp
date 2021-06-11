#include "cctvCrypto.h"

int do_crypt_file(const char *src, const char *dest, int mode) {
  FILE *in, *out;
  int res = 1;
  unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
  int in_len, out_len;
  EVP_CIPHER_CTX *ctx;

  unsigned char key[] = "0123456789abcdeF";
  unsigned char iv[] = "1234567887654321";

  in = fopen(src, "rb");
  if (in == NULL) {
    printf("file open error.\n");
    exit(1);
  }

  out = fopen(dest, "wb");
  if (out == NULL) {
    printf("file open error.\n");
    exit(1);
  }

  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
  EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, mode);
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
  OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

  while (1) {
    in_len = fread(inbuf, 1, 1024, in);

    if (in_len <= 0)
      break;

    if (!EVP_CipherUpdate(ctx, outbuf, &out_len, inbuf, in_len)) {
      printf("EVP_CipherUpdate error.\n");
      res = 0;
      goto exit;
    }
    fwrite(outbuf, 1, out_len, out);
  }

  if (!EVP_CipherFinal_ex(ctx, outbuf, &out_len)) {
    printf("EVP_CipherUpdate error.\n");
    res = 0;
    goto exit;
  }
  fwrite(outbuf, 1, out_len, out);

exit:
  EVP_CIPHER_CTX_free(ctx);
  fclose(in);
  fclose(out);

  return res;
}

int do_crypt_buf(const char *path, unsigned char *buf, int *decrypted_size, int mode) {
  FILE *in;
  int res = 1;
  /* Allow enough space in output buffer for additional block */
  unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
  int in_len, out_len, total_len = 0, encrypted_total_len = 0;
  EVP_CIPHER_CTX *ctx;

  // TODO: Read AES key from outside
  unsigned char key[] = "0123456789abcdeF";
  unsigned char iv[] = "1234567887654321";

  in = fopen(path, "rb");
  if (in == NULL) {
    printf("file open error.\n");
    exit(1);
  }

  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
  EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, mode);
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
  OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

  while (1) {
    in_len = fread(inbuf, 1, 1024, in);

    if (in_len <= 0)
      break;

    if (!EVP_CipherUpdate(ctx, outbuf, &out_len, inbuf, in_len)) {
      printf("EVP_CipherUpdate error.\n");
      res = 0;
      goto exit;
    }
    memcpy(buf + total_len, outbuf, sizeof(int)*out_len);
    encrypted_total_len += in_len;
    total_len += out_len;
  }

  if (!EVP_CipherFinal_ex(ctx, outbuf, &out_len)) {
    EVP_CIPHER_CTX_free(ctx);
    printf("EVP_CipherFinal_ex error.\n");
    res = 0;
    goto exit;
  }

  memcpy(buf + total_len, outbuf, sizeof(int)*out_len);
  total_len += out_len;

  printf("filename = %24s, encrypted_img_size = %6d bytes, decrypted_img_size = %6d bytes\n", path, encrypted_total_len, total_len);

exit:
  *decrypted_size = total_len;
  EVP_CIPHER_CTX_free(ctx);
  fclose(in);

  return res;
}
