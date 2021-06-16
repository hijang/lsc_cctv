#include "cctvCrypto.h"
#include "key_manager.h"

int do_crypt_file(const char *src, const char *dest, int mode) {
  FILE *in, *out;
  int res = 1;
  unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
  int in_len, out_len;
  EVP_CIPHER_CTX *ctx;
  const char desc[] = "fk";

  unsigned char key[256] = { 0, };
  unsigned char iv[] = "1234567887654321";
  int klen = 0;

  if (cctv_request_key(desc, key, &klen) != 0) {
    fprintf(stderr, "request key error.\n");
    return 0;
  }

  in = fopen(src, "rb");
  if (in == NULL) {
    fprintf(stderr, "file open error.\n");
    return 0;;
  }

  out = fopen(dest, "wb");
  if (out == NULL) {
    fprintf(stderr, "file open error.\n");
    return 0;;
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
  const char desc[] = "fk";

  // TODO: Read AES key from outside
  unsigned char key[256] = { 0, };
  unsigned char iv[] = "1234567887654321";
  int klen = 0;
  
  if (cctv_request_key(desc, key, &klen) != 0) {
    fprintf(stderr, "request key error.\n");
    return 0;
  }

  in = fopen(path, "rb");
  if (in == NULL) {
    fprintf(stderr, "file open error.\n");
    return 0;;
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
    memcpy(buf + total_len, outbuf, out_len);
    encrypted_total_len += in_len;
    total_len += out_len;
  }

  if (!EVP_CipherFinal_ex(ctx, outbuf, &out_len)) {
    EVP_CIPHER_CTX_free(ctx);
    printf("EVP_CipherFinal_ex error.\n");
    res = 0;
    goto exit;
  }

  memcpy(buf + total_len, outbuf, out_len);
  total_len += out_len;

  //printf("filename = %24s, encrypted_img_size = %6d bytes, decrypted_img_size = %6d bytes\n", path, encrypted_total_len, total_len);

exit:
  *decrypted_size = total_len;
  EVP_CIPHER_CTX_free(ctx);
  fclose(in);

  return res;
}

int do_encrypt_buf_to_file(std::vector<unsigned char> buffer, std::string filename) {
    int res = 1;
    unsigned char* buf = reinterpret_cast<unsigned char*>(buffer.data());
    FILE *out;
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int in_len=1024, out_len=0, total_len=0, result = buffer.size();
    EVP_CIPHER_CTX *ctx;

    // TODO: Read AES key from outside
    unsigned char key[16] = { 0, };
    unsigned char iv[] = "1234567887654321";
    int klen = 0;
    const char desc[] = "fk";

    if (cctv_request_key(desc, key, &klen) != 0) {
      fprintf(stderr, "request key error.\n");
      return 0;
    } else {
      if (klen != 16) {
        fprintf(stderr, "key length is not expected value \n");
        return 0;
      }
    }

    std::string encodedFileName = "../imgs/";
    encodedFileName += encrypt_filename(filename.c_str());

    out = fopen(encodedFileName.c_str(), "wb");
    if (out == NULL) {
        fprintf(stderr, "file open error.\n");
        return res;
    }

    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, 1);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    while (1) {
        if (!EVP_CipherUpdate(ctx, outbuf, &out_len, buf+total_len, in_len)) {
            printf("EVP_CipherUpdate error.\n");
            res = 0;
            goto exit;
        }
        total_len+=in_len;
        fwrite(outbuf, 1, out_len, out);
        if (total_len >= buffer.size())
            break;
    }

    if (!EVP_CipherFinal_ex(ctx, outbuf, &out_len)) {
        printf("EVP_CipherUpdate error.\n");
        res = 0;
        goto exit;
    } else {
        total_len+=out_len;
    }

    fwrite(outbuf, 1, out_len, out);
    //printf("file encryption is success. size:%d \n", total_len);

exit:
    EVP_CIPHER_CTX_free(ctx);
    fclose(out);

    return res;
}

char* encrypt_filename(const char *filename) {
  unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH] = {0,};
  int out_len, fin_len;
  EVP_CIPHER_CTX *ctx;
  char *encoded_data = NULL;
  char *ptr;
  const char desc[] = "fnk";

  // TODO: Read AES key from outside
  unsigned char key[256] = { 0, };
  unsigned char iv[] = "1234567887654321";
  int klen = 0;

  if (cctv_request_key(desc, key, &klen) != 0) {
    fprintf(stderr, "request key error.\n");
    goto exit;
  }

  // print name
  //printf("filename for encryption = %s\n", filename);

  // encrypt name
  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
  EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, 1);
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
  OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

  if (!EVP_CipherUpdate(ctx, outbuf, &out_len, (const unsigned char*)filename, strlen(filename))) {
    printf("EVP_CipherUpdate error.\n");
    goto exit;
  }

  if (!EVP_CipherFinal_ex(ctx, outbuf + out_len, &fin_len)) {
    printf("EVP_CipherFinal_ex error.\n");
    goto exit;
  }

  // base64 encode
  encoded_data = g_base64_encode((const guchar *)outbuf, out_len + fin_len);
  //printf("base64 encoded data = %s\n", encoded_data);

  ptr = encoded_data;
  while (*ptr) {
    if (*ptr == '/') {
      *ptr = '_';
    }
    ptr++;
  }
  //printf("base64 replaced data = %s\n", encoded_data);

exit:
  EVP_CIPHER_CTX_free(ctx);

  return encoded_data;
}

char* decrypt_filename(const char *filename) {
  unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH] = {0,};
  int out_len, fin_len;
  EVP_CIPHER_CTX *ctx;
  char *buf = NULL;
  char *decoded_data = NULL;
  gsize decoded_size = 0;
  char *ptr, *decrypted_filename;
  const char desc[] = "fnk";

  // TODO: Read AES key from outside
  unsigned char key[256] = { 0, };
  unsigned char iv[] = "1234567887654321";
  int klen = 0;

  if (cctv_request_key(desc, key, &klen) != 0) {
    fprintf(stderr, "request key error.\n");
    goto exit;
  }

  // print name
  //printf("filename for decryption= %s\n", filename);

  if ((buf = strdup((const char*)filename)) == NULL) {
    fprintf(stderr, "strdup error.\n");
    return NULL;
  }

  ptr = buf;
  while (*ptr) {
    if (*ptr == '_') {
      *ptr = '/';
    }
    ptr++;
  }
  //printf("base64 replaced data = %s\n", buf);


  // base64 decode
  decoded_data = (gchar *)g_base64_decode((const gchar *)buf, &decoded_size);

  // decrypt name
  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
  EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, 0);
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
  OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

  if (!EVP_CipherUpdate(ctx, outbuf, &out_len, (const unsigned char*)decoded_data, decoded_size)) {
    printf("EVP_CipherUpdate error.\n");
    goto exit;
  }

  if (!EVP_CipherFinal_ex(ctx, outbuf + out_len, &fin_len)) {
    printf("EVP_CipherFinal_ex error.\n");
    goto exit;
  }

  if ((decrypted_filename = strndup((const char*)outbuf, out_len + fin_len)) == NULL) {
    fprintf(stderr, "strdup error.\n");
    goto exit;
  }

exit:
  EVP_CIPHER_CTX_free(ctx);
  if (buf) {
    free(buf);
  }
  if (decoded_data) {
    free(decoded_data);
  }

  return decrypted_filename;
}
