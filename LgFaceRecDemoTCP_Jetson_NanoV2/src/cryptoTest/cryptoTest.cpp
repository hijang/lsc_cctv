#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "../cctvCrypto.h"

int main (int argc, char *argv[]) {
  char *encrypted_name = NULL;
  char *decrypted_name = NULL;
  if (argc != 2) {
    printf("usage: %s srcpath\n", argv[0]);
    exit(1);
  }
  printf("encryption start..\n");
  if (!(encrypted_name = encrypt_filename(argv[1]))) {
    printf("filename encryption failed.\n");
    exit(1);
  }
  printf("filename = %s\n", encrypted_name);
  if (!do_crypt_file(argv[1], encrypted_name, 1)) {
    printf("file encryption failed.\n");
    free(encrypted_name);
    exit(1);
  }
  printf("encryption done..\n");

  //decrypted_name = decrypt_filename(encrypted_name);
  //do_crypt_file(encrypted_name, "test.jpg", 0);
  //printf("decrypted name = %s\n", decrypted_name);

  if (encrypted_name) {
    free(encrypted_name);
  }
  //if (decrypted_name) {
  //  free(decrypted_name);
  //}

  return 0;
}
