#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "../cctvCrypto.h"

int main (int argc, char *argv[]) {
  if (argc != 3) {
    printf("usage: %s srcpath dstpath\n", argv[0]);
    exit(1);
  }
  printf("encryption start..\n");
  if (!do_crypt_file(argv[1], argv[2], 1)) {
    printf("encryption failed.\n");
    exit(1);
  }
  printf("encryption done..\n");

  return 0;
}
