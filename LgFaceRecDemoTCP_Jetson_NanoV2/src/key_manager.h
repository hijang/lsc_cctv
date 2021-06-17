#ifndef _CCTV_KEY_H_
#define _CCTV_KEY_H_
int cctv_request_key(const char *desc, unsigned char *key, int *len);
int cctv_request_key_alloc(const char *desc, void **key);
int cctv_get_key(char *desc);
#endif
