#ifndef DOHCLIENT_BASE64URL_H_
#define DOHCLIENT_BASE64URL_H_

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

char *base64url_encode(const unsigned char *data,
    int input_length,
    int*output_length);

#ifdef __cplusplus
}
#endif

#endif
