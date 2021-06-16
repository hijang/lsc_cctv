#include <sys/types.h>
extern "C" {
#include <keyutils.h>
}
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "key_manager.h"

int cctv_request_key(const char *desc, unsigned char *key, int *len) {
    char* _key = NULL;
    int key_len = 0;
    key_len = cctv_request_key_alloc(desc, (void**)&_key);
    if (key_len < 0) {
        perror("unable to request key");
        return -1;
    }
    memcpy(key, _key, key_len);
    *len = key_len;
    free(_key);

    return 1;
}

int cctv_request_key_alloc(const char *desc, void **key)
{
    long auth_key = 0;
    long ret = -1;
    /*
     * Workaround on keyctl()
     */
    ret = keyctl_link(KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING);
    if (ret != 0) {
        perror("keyctl_link");
        return -1;
    } else {
        printf("link user to session keyring\n");
    }   

    auth_key = request_key("user", desc, NULL, KEY_SPEC_SESSION_KEYRING);
    if (auth_key == ENOKEY)
        return -1; 
    //printf("Auth key ID:          %lu\n", (long) auth_key);

    int size = keyctl_read_alloc(auth_key, key);
    // printf("%d loaded %s\n", size, *key);

    return size;
}
