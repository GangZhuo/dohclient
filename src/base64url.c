#include "base64url.h"
#include "mleak.h"


static char dns_encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '-', '_'};

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '-'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64url_encode(const unsigned char *data,
                    int input_length,
                    int *output_length,
                    int tail_padding, int dns)
{
	char *table = dns ? dns_encoding_table : encoding_table;
    char *encoded_data;
    int padding, i, j;

    *output_length = 4 * ((input_length + 2) / 3);

    encoded_data = malloc(*output_length + 1);

    if (encoded_data == NULL) return NULL;

    for (i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = table[(triple >> 0 * 6) & 0x3F];
    }

    padding = mod_table[input_length % 3];

    if (tail_padding) {
        for (i = 0; i < padding; i++) {
            encoded_data[*output_length - i - 1] = '=';
        }
    }
    else {
        *output_length -= padding;
    }


    encoded_data[*output_length] = '\0';

    return encoded_data;
}

